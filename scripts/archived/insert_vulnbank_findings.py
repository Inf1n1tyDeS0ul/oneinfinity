#!/usr/bin/env python3
"""One-shot script: insert 6 confirmed vulnbank.org findings into findings.db"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from modules.findings import FindingsDB
from path_manager import findings_db_path

db = FindingsDB(str(findings_db_path()))

findings = [
    dict(
        scan_id="vulnbank-manual-001",
        target="vulnbank.org",
        title="SQL Injection — Authentication Bypass + Admin Escalation",
        severity="critical",
        cvss=9.8,
        vuln_type="sqli",
        url="https://vulnbank.org/login",
        payload="' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
        evidence=(
            "POST /login with username=' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- - "
            "returns HTTP 200 with JSON body containing \"isAdmin\": true. "
            "Admin panel at /sup3r_s3cr3t_admin is fully accessible after receiving the admin JWT. "
            "10-column UNION confirmed by incrementally adding NULLs until no column-count error."
        ),
        tool="manual",
        confidence=1.0,
        status="confirmed",
    ),
    dict(
        scan_id="vulnbank-manual-001",
        target="vulnbank.org",
        title="SSRF — AWS Instance Metadata Service (169.254.169.254)",
        severity="critical",
        cvss=9.1,
        vuln_type="ssrf",
        url="https://vulnbank.org/upload_profile_picture_url",
        payload='{"image_url": "http://169.254.169.254/latest/meta-data/"}',
        evidence=(
            "POST /upload_profile_picture_url with body {\"image_url\": \"http://169.254.169.254/latest/meta-data/\"} "
            "returns HTTP 200 with Content-Length: 124, confirming the server fetched the AWS IMDS endpoint. "
            "Response body contains IMDS metadata directory listing. "
            "Further requests to /latest/meta-data/iam/security-credentials/ enumerate IAM role names."
        ),
        tool="manual",
        confidence=1.0,
        status="confirmed",
    ),
    dict(
        scan_id="vulnbank-manual-001",
        target="vulnbank.org",
        title="IDOR — Broken Object-Level Authorization on Transactions",
        severity="high",
        cvss=7.5,
        vuln_type="idor",
        url="https://vulnbank.org/transactions/6186686091",
        payload="GET /transactions/6186686091 with another user's JWT in Authorization header",
        evidence=(
            "Authenticated as user A (account 1234567890), sending GET /transactions/6186686091 "
            "(account belonging to user B) with user A's valid JWT returns HTTP 200 with user B's "
            "full transaction history including amounts, descriptions, and counterparty accounts. "
            "No authorization check exists server-side — any authenticated user can access any account's data."
        ),
        tool="manual",
        confidence=1.0,
        status="confirmed",
    ),
    dict(
        scan_id="vulnbank-manual-001",
        target="vulnbank.org",
        title="CORS Misconfiguration — Arbitrary Origin Reflected",
        severity="high",
        cvss=7.1,
        vuln_type="cors",
        url="https://vulnbank.org/ (all API endpoints)",
        payload="Origin: https://evil.attacker.com",
        evidence=(
            "OPTIONS /login with header 'Origin: https://evil.attacker.com' returns: "
            "Access-Control-Allow-Origin: https://evil.attacker.com, "
            "Access-Control-Allow-Credentials: true, "
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS. "
            "Any origin is reflected verbatim. Combined with ACAO: true, this allows a malicious "
            "cross-origin page to make authenticated requests and read responses."
        ),
        tool="manual",
        confidence=1.0,
        status="confirmed",
    ),
    dict(
        scan_id="vulnbank-manual-001",
        target="vulnbank.org",
        title="Information Disclosure — Debug Data in API Responses",
        severity="medium",
        cvss=5.3,
        vuln_type="info_disclosure",
        url="https://vulnbank.org/register, https://vulnbank.org/login",
        payload="POST /register with new user credentials",
        evidence=(
            "POST /register response body includes a 'debug_data' key containing: "
            "raw_data.password (plaintext password as submitted), is_admin (boolean), "
            "and account_number. Example excerpt: "
            "{\"debug_data\": {\"raw_data\": {\"password\": \"TestPass123!\"}, "
            "\"is_admin\": false, \"account_number\": \"9876543210\"}}. "
            "POST /login similarly exposes debug_data.raw_data in the response."
        ),
        tool="manual",
        confidence=1.0,
        status="confirmed",
    ),
    dict(
        scan_id="vulnbank-manual-001",
        target="vulnbank.org",
        title="Exposed OpenAPI Specification with Internal Route Listing",
        severity="medium",
        cvss=5.3,
        vuln_type="info_disclosure",
        url="https://vulnbank.org/static/openapi.json",
        payload="GET /static/openapi.json (no authentication required)",
        evidence=(
            "GET /static/openapi.json returns HTTP 200 with the full OpenAPI 3.0 specification. "
            "The spec exposes hidden/internal paths including: /sup3r_s3cr3t_admin (admin panel), "
            "SSRF demo route /upload_profile_picture_url with parameter documentation, "
            "and internal API versioning details. No authentication or access control on this endpoint."
        ),
        tool="manual",
        confidence=1.0,
        status="confirmed",
    ),
]

print(f"Inserting {len(findings)} findings into findings.db...")
for f in findings:
    fid = db.add(**f)
    print(f"  [+] {fid} — {f['severity'].upper()} — {f['title']}")

db.close()
print("\nDone. All findings inserted.")
