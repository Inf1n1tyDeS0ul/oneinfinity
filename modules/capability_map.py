"""
Tool Capability Map — One&Infinity
==========================================
Static database describing every tool's:
  - Vulnerability classes it detects
  - Required inputs (and their types)
  - Expected output fields
  - Confidence level of detections
  - Execution prerequisites (what must run first)
  - Cost profile (time, rate-limit sensitivity, noise level)
  - Whether root/elevated privileges are needed

This module is read-only data. Nothing is executed here.
Query it with CapabilityMap.get() or CapabilityMap.tools_for_vuln().
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ── Vuln class constants ──────────────────────────────────────────────────────
# Canonical vulnerability class names used across the entire assistant.

class Vuln:
    SQLI           = "SQL Injection"
    XSS            = "Cross-Site Scripting (XSS)"
    SSRF           = "Server-Side Request Forgery (SSRF)"
    IDOR           = "Insecure Direct Object Reference (IDOR)"
    CORS           = "CORS Misconfiguration"
    CRLF           = "CRLF Injection"
    CMD_INJECTION  = "OS Command Injection"
    OPEN_REDIRECT  = "Open Redirect"
    SSTI           = "Server-Side Template Injection (SSTI)"
    XXE            = "XML External Entity (XXE)"
    LFI            = "Local File Inclusion (LFI)"
    SUBDOMAIN_TAKE = "Subdomain Takeover"
    EXPOSED_FILES  = "Exposed Sensitive Files"
    MISCONFIG      = "Security Misconfiguration"
    MISSING_HEADERS= "Missing Security Headers"
    INFO_LEAK      = "Information Disclosure"
    DEFAULT_CREDS  = "Default Credentials"
    BROKEN_AUTH    = "Broken Authentication"
    JWT_ATTACK     = "JWT Vulnerability"
    SECRET_EXPOSURE= "Secret / Credential Exposure"
    S3_MISCONFIG   = "Cloud Storage Misconfiguration"
    OPEN_PORT      = "Exposed Network Service"
    OUTDATED_SW    = "Outdated Software / Known CVE"
    PARAM_POLLUTION= "HTTP Parameter Pollution"
    HOST_HEADER    = "Host Header Injection"
    CACHE_POISON   = "Cache Poisoning"
    API_EXPOSURE   = "Undocumented API Endpoint"
    # Extended vuln classes — added to close OWASP Top 10 gaps
    DESERIALIZATION     = "Insecure Deserialization"
    RACE_CONDITION      = "Race Condition"
    FILE_UPLOAD         = "Insecure File Upload"
    OAUTH_FLAW          = "OAuth/OIDC Vulnerability"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    WEBSOCKET_VULN      = "WebSocket Security Issue"
    MFA_BYPASS          = "MFA/2FA Bypass"
    RATE_LIMIT_BYPASS   = "Missing Rate Limiting"
    PII_EXPOSURE        = "PII Exposure in API Response"
    PAYMENT_TAMPERING   = "Payment/Price Tampering"
    CLICKJACKING        = "Clickjacking"
    DOM_XSS             = "DOM-based XSS"
    SOURCE_MAP_EXPOSURE = "Exposed JavaScript Source Map"
    # OWASP WSTG v4.2 gap checks
    WEAK_TLS            = "Weak TLS Configuration"
    TLS_CERT_ISSUE      = "TLS Certificate Issue"
    BACKUP_FILES        = "Backup/Archive File Exposed"
    COOKIE_ATTRS        = "Insecure Cookie Attributes"
    CSRF                = "Cross-Site Request Forgery (CSRF)"
    SESSION_FIXATION    = "Session Fixation"
    SESSION_TIMEOUT     = "Missing Session Timeout"
    ACCOUNT_ENUM        = "Account Enumeration via Timing"
    WEAK_PASSWORD_POLICY= "Weak Password Policy"
    SAML_VULN           = "SAML Assertion Vulnerability"
    LDAP_INJECTION      = "LDAP Injection"
    MAIL_HEADER_INJ     = "Mail Header Injection"
    CODE_INJECTION      = "Code Injection"
    CSV_INJECTION       = "CSV Injection"
    POSTMESSAGE_HIJACK  = "postMessage Hijacking Risk"
    WEB_STORAGE         = "Sensitive Data in Web Storage"
    INSECURE_RNG        = "Insecure Random Number Generation"
    WEAK_CRYPTO         = "Weak Encryption Algorithm"
    PADDING_ORACLE      = "Padding Oracle"
    SERVICE_WORKER      = "Service Worker Abuse Risk"
    WEBRTC_LEAK         = "WebRTC IP Leakage"
    GRPC_SOAP_EXPOSED   = "gRPC/SOAP Endpoint Exposed"
    CODE_INJECTION_EVAL = "Code Injection via eval"


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class InputSpec:
    name: str
    type: str          # domain | url | host | file | list[url] | list[str] | token | path
    required: bool = True
    description: str = ""


@dataclass
class OutputField:
    name: str
    type: str          # list[str] | list[dict] | dict | str | bool
    description: str = ""


@dataclass
class ToolCapability:
    name: str
    category: str
    description: str

    # What it detects
    detects: list[str] = field(default_factory=list)

    # Inputs
    inputs: list[InputSpec] = field(default_factory=list)

    # Outputs
    outputs: list[OutputField] = field(default_factory=list)

    # Prerequisites: what phase/tool outputs must exist first
    requires_phase: list[str] = field(default_factory=list)   # e.g. ["subdomain", "http"]
    feeds_into: list[str] = field(default_factory=list)        # phases/tools that consume its output

    # Confidence level for each detected vuln class: low | medium | high
    confidence: dict[str, str] = field(default_factory=dict)

    # Cost profile
    typical_duration_sec: int = 60         # typical runtime
    rate_sensitive: bool = False           # does it hammer the target hard?
    needs_root: bool = False               # requires sudo/root
    noise_level: str = "medium"           # low | medium | high  (how detectable by WAF/IDS)
    passive: bool = False                  # passive only (no active requests to target)

    # Execution notes
    notes: str = ""


# ── The full capability database ──────────────────────────────────────────────

CAPABILITIES: dict[str, ToolCapability] = {

    # =========================================================================
    # SUBDOMAIN ENUMERATION
    # =========================================================================

    "subfinder": ToolCapability(
        name="subfinder",
        category="subdomain",
        description="Fast passive subdomain enumeration using 40+ data sources "
                    "(certificate transparency, DNS datasets, APIs).",
        detects=[Vuln.SUBDOMAIN_TAKE, Vuln.INFO_LEAK],
        inputs=[
            InputSpec("domain", "domain", True, "Root domain to enumerate"),
        ],
        outputs=[
            OutputField("subdomains", "list[str]", "Discovered subdomain FQDNs"),
            OutputField("count", "int", "Total unique subdomains found"),
        ],
        requires_phase=[],
        feeds_into=["http", "dns", "ports", "vuln"],
        confidence={Vuln.SUBDOMAIN_TAKE: "medium", Vuln.INFO_LEAK: "low"},
        typical_duration_sec=60,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Best single tool for subdomain coverage. Combine with amass for maximum breadth.",
    ),

    "amass": ToolCapability(
        name="amass",
        category="subdomain",
        description="OWASP Amass: deep OSINT subdomain enumeration with ASN mapping, "
                    "IP ranges, and graph-based asset correlation.",
        detects=[Vuln.INFO_LEAK, Vuln.SUBDOMAIN_TAKE],
        inputs=[
            InputSpec("domain", "domain", True, "Root domain"),
        ],
        outputs=[
            OutputField("subdomains", "list[str]", "Discovered subdomains"),
            OutputField("count", "int", "Total subdomains"),
        ],
        requires_phase=[],
        feeds_into=["http", "dns", "ports"],
        confidence={Vuln.SUBDOMAIN_TAKE: "low"},
        typical_duration_sec=300,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Slower than subfinder but finds ASN-linked assets subfinder misses. "
              "Use passive mode (-passive) in bug bounty to avoid active DNS bruteforce.",
    ),

    "assetfinder": ToolCapability(
        name="assetfinder",
        category="subdomain",
        description="Lightweight subdomain finder using certificate transparency and DNS sources.",
        detects=[Vuln.SUBDOMAIN_TAKE, Vuln.INFO_LEAK],
        inputs=[InputSpec("domain", "domain", True)],
        outputs=[OutputField("subdomains", "list[str]")],
        requires_phase=[],
        feeds_into=["http", "dns"],
        confidence={Vuln.SUBDOMAIN_TAKE: "medium", Vuln.INFO_LEAK: "low"},
        typical_duration_sec=30,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Fast and quiet. Good as a quick first pass before subfinder.",
    ),

    "findomain": ToolCapability(
        name="findomain",
        category="subdomain",
        description="Certificate transparency and DNS-based subdomain discovery.",
        detects=[Vuln.SUBDOMAIN_TAKE, Vuln.INFO_LEAK],
        inputs=[InputSpec("domain", "domain", True)],
        outputs=[OutputField("subdomains", "list[str]")],
        requires_phase=[],
        feeds_into=["http", "dns"],
        confidence={Vuln.SUBDOMAIN_TAKE: "medium", Vuln.INFO_LEAK: "low"},
        typical_duration_sec=20,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
    ),

    "chaos": ToolCapability(
        name="chaos",
        category="subdomain",
        description="ProjectDiscovery Chaos dataset — pre-indexed subdomain corpus for known bug bounty programs.",
        detects=[Vuln.SUBDOMAIN_TAKE, Vuln.INFO_LEAK],
        inputs=[
            InputSpec("domain", "domain", True),
            InputSpec("key", "str", False, "Chaos API key (env: CHAOS_KEY)"),
        ],
        outputs=[OutputField("subdomains", "list[str]")],
        requires_phase=[],
        feeds_into=["http", "dns"],
        confidence={Vuln.SUBDOMAIN_TAKE: "medium", Vuln.INFO_LEAK: "low"},
        typical_duration_sec=10,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Requires free API key from chaos.projectdiscovery.io. Instant results from their dataset.",
    ),

    "sublist3r": ToolCapability(
        name="sublist3r",
        category="subdomain",
        description="Multi-source passive subdomain enumeration (Shodan, DNSdumpster, Google, etc.).",
        detects=[Vuln.SUBDOMAIN_TAKE, Vuln.INFO_LEAK],
        inputs=[InputSpec("domain", "domain", True)],
        outputs=[OutputField("subdomains", "list[str]")],
        requires_phase=[],
        feeds_into=["http", "dns"],
        confidence={Vuln.SUBDOMAIN_TAKE: "medium", Vuln.INFO_LEAK: "low"},
        typical_duration_sec=120,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Slower than subfinder due to scraping. Good for covering sources subfinder misses.",
    ),

    # =========================================================================
    # DNS
    # =========================================================================

    "dnsx": ToolCapability(
        name="dnsx",
        category="dns",
        description="Fast multi-threaded DNS resolver. Resolves subdomains, extracts CNAME chains, "
                    "detects wildcards and dangling DNS records.",
        detects=[Vuln.SUBDOMAIN_TAKE, Vuln.INFO_LEAK],
        inputs=[
            InputSpec("domains", "list[str]", True, "List of subdomains to resolve"),
        ],
        outputs=[
            OutputField("records", "list[dict]", "DNS records per domain: A, AAAA, CNAME, MX, NS"),
            OutputField("dangling_cnames", "list[str]", "CNAMEs pointing to unclaimed services"),
        ],
        requires_phase=["subdomain"],
        feeds_into=["http", "vuln"],
        confidence={Vuln.SUBDOMAIN_TAKE: "high"},
        typical_duration_sec=30,
        rate_sensitive=False,
        noise_level="low",
        passive=False,
        notes="Run after subdomain enumeration. Dangling CNAME → subdomain takeover. "
              "Check for services: GitHub Pages, Heroku, Fastly, Shopify, etc.",
    ),

    # =========================================================================
    # HTTP PROBING
    # =========================================================================

    "httpx": ToolCapability(
        name="httpx",
        category="http",
        description="Fast HTTP/HTTPS prober. Detects alive hosts, status codes, "
                    "response headers, titles, and technology stack.",
        detects=[
            Vuln.MISSING_HEADERS,
            Vuln.INFO_LEAK,
            Vuln.MISCONFIG,
        ],
        inputs=[
            InputSpec("targets", "list[str]", True, "List of hosts or URLs to probe"),
        ],
        outputs=[
            OutputField("hosts", "list[dict]", "Per-host: url, status_code, title, tech, headers, content_length"),
            OutputField("count", "int", "Number of alive hosts"),
        ],
        requires_phase=["subdomain"],
        feeds_into=["crawl", "content", "vuln", "ports"],
        confidence={
            Vuln.MISSING_HEADERS: "medium",
            Vuln.INFO_LEAK: "medium",
        },
        typical_duration_sec=60,
        rate_sensitive=False,
        noise_level="low",
        notes="Critical pivot step — everything downstream depends on alive host list. "
              "Run with -tech-detect to fingerprint stack for targeted attacks.",
    ),

    # =========================================================================
    # PORT SCANNING
    # =========================================================================

    "naabu": ToolCapability(
        name="naabu",
        category="ports",
        description="Fast SYN/TCP port scanner by ProjectDiscovery. Discovers open ports "
                    "across a large host list efficiently.",
        detects=[Vuln.OPEN_PORT, Vuln.MISCONFIG],
        inputs=[
            InputSpec("target", "host", True, "Host or IP to scan"),
            InputSpec("ports", "str", False, "Port range (default: top-1000)"),
        ],
        outputs=[
            OutputField("open_ports", "list[dict]", "port, protocol, host"),
            OutputField("count", "int"),
        ],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={Vuln.OPEN_PORT: "high", Vuln.MISCONFIG: "low"},
        typical_duration_sec=30,
        rate_sensitive=False,
        noise_level="medium",
        notes="Best for fast initial port discovery. Feed results into nmap for service detection.",
    ),

    "nmap": ToolCapability(
        name="nmap",
        category="ports",
        description="Network mapper — port scanning, service/version detection, OS fingerprinting, "
                    "and script-based vulnerability detection via NSE scripts.",
        detects=[
            Vuln.OPEN_PORT,
            Vuln.OUTDATED_SW,
            Vuln.DEFAULT_CREDS,
            Vuln.MISCONFIG,
            Vuln.INFO_LEAK,
        ],
        inputs=[
            InputSpec("target", "host", True, "Target host, IP, or CIDR"),
            InputSpec("flags", "str", False, "nmap flags (default: -sV -T4 --open)"),
        ],
        outputs=[
            OutputField("open_ports", "list[dict]", "port, protocol, service, version"),
        ],
        requires_phase=["subdomain"],
        feeds_into=["vuln"],
        confidence={
            Vuln.OPEN_PORT: "high",
            Vuln.OUTDATED_SW: "medium",
            Vuln.DEFAULT_CREDS: "low",
        },
        typical_duration_sec=120,
        rate_sensitive=True,
        noise_level="high",
        notes="Use --open to filter open ports only. -sV for service detection. "
              "NSE scripts (--script=vuln) add vuln detection but increase noise significantly.",
    ),

    "masscan": ToolCapability(
        name="masscan",
        category="ports",
        description="Ultra-fast port scanner — scans entire internet at 10M+ packets/sec. "
                    "Best for scanning large CIDR ranges.",
        detects=[Vuln.OPEN_PORT],
        inputs=[
            InputSpec("target", "host", True, "IP or CIDR range"),
            InputSpec("ports", "str", False, "Port range (default: 0-65535)"),
            InputSpec("rate", "int", False, "Packets per second"),
        ],
        outputs=[OutputField("open_ports", "list[dict]", "ip, port, proto")],
        requires_phase=[],
        feeds_into=["vuln"],
        confidence={Vuln.OPEN_PORT: "high"},
        typical_duration_sec=60,
        rate_sensitive=False,
        noise_level="high",
        needs_root=True,
        notes="Needs root for raw socket access. Use for broad CIDR sweeps, "
              "then feed discovered ports to nmap for service identification.",
    ),

    "rustscan": ToolCapability(
        name="rustscan",
        category="ports",
        description="Modern fast port scanner written in Rust. Discovers all open ports "
                    "quickly then hands off to nmap.",
        detects=[Vuln.OPEN_PORT],
        inputs=[InputSpec("target", "host", True)],
        outputs=[OutputField("open_ports", "list[dict]")],
        requires_phase=[],
        feeds_into=["vuln"],
        confidence={Vuln.OPEN_PORT: "high"},
        typical_duration_sec=20,
        rate_sensitive=False,
        noise_level="medium",
        notes="Faster than nmap for initial discovery. Automatically calls nmap on found ports.",
    ),

    # =========================================================================
    # WEB CRAWLING & URL DISCOVERY
    # =========================================================================

    "katana": ToolCapability(
        name="katana",
        category="crawl",
        description="Next-gen web crawler by ProjectDiscovery. Handles JavaScript rendering, "
                    "form discovery, and structured output of all discovered endpoints.",
        detects=[Vuln.API_EXPOSURE, Vuln.INFO_LEAK],
        inputs=[
            InputSpec("target", "url", True, "Starting URL to crawl"),
            InputSpec("depth", "int", False, "Crawl depth (default: 3)"),
            InputSpec("js_crawl", "bool", False, "Enable JS parsing (default: true)"),
        ],
        outputs=[
            OutputField("urls", "list[str]", "All discovered URLs/endpoints"),
            OutputField("count", "int"),
        ],
        requires_phase=["http"],
        feeds_into=["content", "vuln"],
        confidence={Vuln.API_EXPOSURE: "medium"},
        typical_duration_sec=180,
        rate_sensitive=True,
        noise_level="medium",
        notes="Best crawler for modern SPAs and React/Vue apps. "
              "Use -jc for JavaScript crawling. Feeds directly into dalfox and sqlmap.",
    ),

    "hakrawler": ToolCapability(
        name="hakrawler",
        category="crawl",
        description="Simple, fast web crawler focused on link extraction from HTML and JS.",
        detects=[Vuln.INFO_LEAK, Vuln.EXPOSED_FILES, Vuln.API_EXPOSURE],
        inputs=[InputSpec("url", "url", True, "Target URL (read from stdin)")],
        outputs=[OutputField("urls", "list[str]", "Discovered URLs and paths")],
        requires_phase=["http"],
        feeds_into=["content", "vuln"],
        confidence={Vuln.INFO_LEAK: "low", Vuln.API_EXPOSURE: "low"},
        typical_duration_sec=60,
        rate_sensitive=True,
        noise_level="low",
        notes="Lightweight alternative to katana. Good for server-rendered sites.",
    ),

    "gauplus": ToolCapability(
        name="gauplus",
        category="crawl",
        description="Fetches known URLs from Wayback Machine, Common Crawl, and OTX. "
                    "Discovers historical endpoints including old parameters.",
        detects=[Vuln.INFO_LEAK, Vuln.EXPOSED_FILES],
        inputs=[InputSpec("domain", "domain", True)],
        outputs=[OutputField("urls", "list[str]", "Historical URLs (may include removed endpoints)")],
        requires_phase=[],
        feeds_into=["content", "vuln"],
        confidence={Vuln.INFO_LEAK: "low"},
        typical_duration_sec=60,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Passive — no requests to target. Historical URLs often contain "
              "old vulnerable parameters (SQLi, XSS, SSRF) that are still alive.",
    ),

    "waybackurls": ToolCapability(
        name="waybackurls",
        category="crawl",
        description="Fetches all Wayback Machine snapshots of a domain — "
                    "excellent for finding old parameters and forgotten endpoints.",
        detects=[Vuln.INFO_LEAK, Vuln.EXPOSED_FILES],
        inputs=[InputSpec("domain", "domain", True)],
        outputs=[OutputField("urls", "list[str]")],
        requires_phase=[],
        feeds_into=["vuln"],
        confidence={Vuln.INFO_LEAK: "low"},
        typical_duration_sec=60,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
    ),

    "paramspider": ToolCapability(
        name="paramspider",
        category="crawl",
        description="Discovers URL parameters from Wayback Machine and live crawling. "
                    "Produces parameterized URLs ready for fuzzing.",
        detects=[Vuln.INFO_LEAK, Vuln.PARAM_POLLUTION, Vuln.EXPOSED_FILES],
        inputs=[InputSpec("domain", "domain", True)],
        outputs=[
            OutputField("urls", "list[str]", "URLs with parameter placeholders (param=FUZZ)"),
        ],
        requires_phase=[],
        feeds_into=["vuln"],
        confidence={Vuln.INFO_LEAK: "low", Vuln.PARAM_POLLUTION: "medium"},
        typical_duration_sec=60,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Primary feeder for XSS (dalfox/kxss) and SQLi (sqlmap) scanners. "
              "Output goes directly to gf for pattern-based filtering.",
    ),

    # =========================================================================
    # CONTENT DISCOVERY
    # =========================================================================

    "ffuf": ToolCapability(
        name="ffuf",
        category="content",
        description="Fast web fuzzer for directory/file discovery, parameter fuzzing, "
                    "and virtual host discovery. Highly configurable with autocalibration.",
        detects=[
            Vuln.EXPOSED_FILES,
            Vuln.MISCONFIG,
            Vuln.BROKEN_AUTH,
            Vuln.INFO_LEAK,
            Vuln.API_EXPOSURE,
        ],
        inputs=[
            InputSpec("url", "url", True, "Target URL (use FUZZ keyword)"),
            InputSpec("wordlist", "path", False, "Wordlist file (auto-detected)"),
            InputSpec("extensions", "str", False, "File extensions to append"),
        ],
        outputs=[
            OutputField("found", "list[dict]", "path, url, status_code, content_length"),
            OutputField("count", "int"),
        ],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={
            Vuln.EXPOSED_FILES: "high",
            Vuln.MISCONFIG: "medium",
            Vuln.API_EXPOSURE: "medium",
        },
        typical_duration_sec=300,
        rate_sensitive=True,
        noise_level="high",
        notes="Best content discovery tool. Use -ac (autocalibrate) to filter false positives. "
              "Run with SecLists raft-medium-directories for best coverage.",
    ),

    "gobuster": ToolCapability(
        name="gobuster",
        category="content",
        description="Directory/DNS/vhost brute-forcer. Fast and reliable for directory discovery.",
        detects=[Vuln.EXPOSED_FILES, Vuln.MISCONFIG, Vuln.API_EXPOSURE],
        inputs=[
            InputSpec("url", "url", True),
            InputSpec("wordlist", "path", False),
        ],
        outputs=[OutputField("found", "list[str]", "Discovered paths")],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={Vuln.EXPOSED_FILES: "high"},
        typical_duration_sec=180,
        rate_sensitive=True,
        noise_level="high",
        notes="Good fallback when ffuf is unavailable. Use 'dns' mode for subdomain brute-force.",
    ),

    "dirsearch": ToolCapability(
        name="dirsearch",
        category="content",
        description="Advanced web path scanner with built-in wordlist and extension handling.",
        detects=[Vuln.EXPOSED_FILES, Vuln.MISCONFIG, Vuln.INFO_LEAK],
        inputs=[
            InputSpec("url", "url", True),
            InputSpec("extensions", "str", False),
        ],
        outputs=[
            OutputField("found", "list[dict]", "path, status, size"),
        ],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={Vuln.EXPOSED_FILES: "high"},
        typical_duration_sec=240,
        rate_sensitive=True,
        noise_level="high",
        notes="Has a built-in wordlist so works without SecLists. "
              "Good for extension-focused scanning (.bak, .old, .backup).",
    ),

    "wfuzz": ToolCapability(
        name="wfuzz",
        category="content",
        description="Web application fuzzer for parameters, headers, cookies, and POST data. "
                    "More flexible than ffuf for complex injection scenarios.",
        detects=[Vuln.SQLI, Vuln.XSS, Vuln.SSRF, Vuln.CMD_INJECTION, Vuln.MISCONFIG],
        inputs=[
            InputSpec("url", "url", True, "URL with FUZZ keyword"),
            InputSpec("wordlist", "path", False),
        ],
        outputs=[OutputField("results", "list[dict]")],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={
            Vuln.SQLI: "low",
            Vuln.XSS: "low",
        },
        typical_duration_sec=300,
        rate_sensitive=True,
        noise_level="high",
        notes="Best for custom fuzzing scenarios (auth bypass, rate limiting bypass, "
              "cookie/header fuzzing). Use --hc to filter status codes.",
    ),

    # =========================================================================
    # VULNERABILITY SCANNING
    # =========================================================================

    "nuclei": ToolCapability(
        name="nuclei",
        category="vuln",
        description="Template-based vulnerability scanner. 9,000+ community templates covering "
                    "CVEs, misconfigs, exposed files, default creds, and dozens of vuln classes.",
        detects=[
            Vuln.SQLI, Vuln.XSS, Vuln.SSRF, Vuln.SSTI, Vuln.XXE, Vuln.LFI,
            Vuln.CORS, Vuln.CRLF, Vuln.OPEN_REDIRECT, Vuln.EXPOSED_FILES,
            Vuln.MISCONFIG, Vuln.DEFAULT_CREDS, Vuln.BROKEN_AUTH, Vuln.INFO_LEAK,
            Vuln.SUBDOMAIN_TAKE, Vuln.OUTDATED_SW, Vuln.HOST_HEADER, Vuln.CACHE_POISON,
            Vuln.SECRET_EXPOSURE, Vuln.MISSING_HEADERS,
        ],
        inputs=[
            InputSpec("target", "url", True, "Target URL or host"),
            InputSpec("templates", "path", False, "Template path or tag (default: all)"),
            InputSpec("severity", "str", False, "Comma-separated severities to run"),
        ],
        outputs=[
            OutputField("findings", "list[dict]",
                        "template_id, name, severity, host, matched_at, description, tags"),
            OutputField("count", "int"),
        ],
        requires_phase=["http"],
        feeds_into=["report"],
        confidence={
            Vuln.MISCONFIG: "high",
            Vuln.EXPOSED_FILES: "high",
            Vuln.DEFAULT_CREDS: "high",
            Vuln.SUBDOMAIN_TAKE: "high",
            Vuln.OUTDATED_SW: "medium",
            Vuln.SQLI: "medium",
            Vuln.XSS: "medium",
            Vuln.SSRF: "medium",
            Vuln.CORS: "medium",
            Vuln.CRLF: "medium",
            Vuln.INFO_LEAK: "high",
        },
        typical_duration_sec=600,
        rate_sensitive=True,
        noise_level="medium",
        notes="Most versatile tool in the toolchain. Run with -severity medium,high,critical "
              "to avoid low-severity noise. Update templates weekly with nuclei -update-templates. "
              "Use -tags for focused scanning: nuclei -tags xss,sqli,ssrf.",
    ),

    "dalfox": ToolCapability(
        name="dalfox",
        category="vuln",
        description="Parameter analysis and XSS hunter. Automatically analyzes parameters, "
                    "detects injection contexts, and generates working XSS payloads.",
        detects=[Vuln.XSS, Vuln.DOM_XSS, Vuln.OPEN_REDIRECT, Vuln.HOST_HEADER],
        inputs=[
            InputSpec("url", "url", True, "Target URL with parameters"),
            InputSpec("params", "list[str]", False, "Specific parameters to test"),
        ],
        outputs=[
            OutputField("findings", "list[dict]",
                        "type (reflected/stored/dom), url, parameter, payload, context"),
        ],
        requires_phase=["http", "crawl"],
        feeds_into=["report"],
        confidence={Vuln.XSS: "high", Vuln.DOM_XSS: "high", Vuln.OPEN_REDIRECT: "medium"},
        typical_duration_sec=120,
        rate_sensitive=True,
        noise_level="medium",
        notes="Best XSS tool in the toolchain. More accurate than kxss/xssstrike "
              "due to context-aware payload generation. Handles WAF bypass automatically. "
              "Feed URLs from paramspider/waybackurls.",
    ),

    "sqlmap": ToolCapability(
        name="sqlmap",
        category="vuln",
        description="Automatic SQL injection detection and exploitation. Supports all major "
                    "DBMS and injection types: error-based, blind, time-based, UNION.",
        detects=[Vuln.SQLI],
        inputs=[
            InputSpec("url", "url", True, "Target URL"),
            InputSpec("params", "str", False, "Specific parameter(s) to test"),
            InputSpec("data", "str", False, "POST data body"),
            InputSpec("level", "int", False, "Test depth 1-5 (default: 1)"),
            InputSpec("risk", "int", False, "Risk level 1-3 (default: 1)"),
        ],
        outputs=[
            OutputField("vulnerable_parameters", "list[str]"),
            OutputField("injection_types", "list[str]"),
            OutputField("is_vulnerable", "bool"),
        ],
        requires_phase=["http", "crawl"],
        feeds_into=["report"],
        confidence={Vuln.SQLI: "high"},
        typical_duration_sec=300,
        rate_sensitive=True,
        noise_level="high",
        notes="Use --batch for non-interactive mode. Start with level=1,risk=1. "
              "Only run on endpoints with numeric/string parameters. "
              "Pre-filter candidates with gf sqli pattern.",
    ),

    "kxss": ToolCapability(
        name="kxss",
        category="vuln",
        description="Finds reflected XSS by checking which special characters "
                    "are reflected unescaped in HTTP responses.",
        detects=[Vuln.XSS],
        inputs=[InputSpec("urls", "list[str]", True, "URLs to check (from stdin)")],
        outputs=[
            OutputField("reflected", "list[str]", "URLs where special chars reflect unescaped"),
        ],
        requires_phase=["crawl"],
        feeds_into=["vuln"],   # feeds dalfox for confirmation
        confidence={Vuln.XSS: "low"},   # indicator, not confirmed XSS
        typical_duration_sec=60,
        rate_sensitive=True,
        noise_level="low",
        notes="Triage tool — use output to feed dalfox for confirmation. "
              "Low FP rate but only detects reflected, not DOM or stored XSS.",
    ),

    "crlfuzz": ToolCapability(
        name="crlfuzz",
        category="vuln",
        description="Tests for CRLF injection (\\r\\n in HTTP responses). "
                    "Enables HTTP response splitting, cookie injection, and XSS via headers.",
        detects=[Vuln.CRLF, Vuln.CACHE_POISON, Vuln.HOST_HEADER],
        inputs=[InputSpec("target", "url", True)],
        outputs=[
            OutputField("vulnerable", "bool"),
            OutputField("findings", "list[str]", "Confirmed vulnerable URLs"),
        ],
        requires_phase=["http"],
        feeds_into=["report"],
        confidence={Vuln.CRLF: "high", Vuln.CACHE_POISON: "medium", Vuln.HOST_HEADER: "medium"},
        typical_duration_sec=30,
        rate_sensitive=True,
        noise_level="medium",
        notes="Low false-positive rate — if flagged as vulnerable, it's almost certainly real.",
    ),

    "nikto": ToolCapability(
        name="nikto",
        category="vuln",
        description="Classic web server scanner. Checks for dangerous files, outdated software, "
                    "default configs, and common misconfigurations.",
        detects=[
            Vuln.EXPOSED_FILES, Vuln.OUTDATED_SW, Vuln.MISCONFIG,
            Vuln.DEFAULT_CREDS, Vuln.INFO_LEAK,
        ],
        inputs=[InputSpec("target", "host", True, "Target host/URL")],
        outputs=[OutputField("results", "list[dict]")],
        requires_phase=["http"],
        feeds_into=["report"],
        confidence={
            Vuln.EXPOSED_FILES: "high",
            Vuln.OUTDATED_SW: "medium",
            Vuln.MISCONFIG: "medium",
        },
        typical_duration_sec=180,
        rate_sensitive=True,
        noise_level="high",
        notes="Noisy — will trigger WAF/IDS. High false-positive rate. "
              "Use for comprehensive baseline scan, then verify findings manually.",
    ),

    "whatweb": ToolCapability(
        name="whatweb",
        category="vuln",
        description="Web technology fingerprinter. Identifies CMS, frameworks, "
                    "server versions, and JavaScript libraries.",
        detects=[Vuln.OUTDATED_SW, Vuln.INFO_LEAK],
        inputs=[
            InputSpec("target", "url", True),
            InputSpec("aggression", "int", False, "1-4 aggression level"),
        ],
        outputs=[
            OutputField("technologies", "list[dict]", "technology name, version, confidence"),
        ],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={Vuln.OUTDATED_SW: "medium", Vuln.INFO_LEAK: "medium"},
        typical_duration_sec=15,
        rate_sensitive=False,
        noise_level="low",
        notes="Fast fingerprinting. Use output to target nuclei templates — "
              "e.g., if WordPress detected, run nuclei -tags wordpress.",
    ),

    "xssstrike": ToolCapability(
        name="xssstrike",
        category="vuln",
        description="XSS scanner with a custom fuzzing engine, WAF fingerprinting, "
                    "and context-aware payload generation.",
        detects=[Vuln.XSS, Vuln.DOM_XSS, Vuln.OPEN_REDIRECT],
        inputs=[
            InputSpec("url", "url", True),
            InputSpec("params", "str", False),
        ],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["http", "crawl"],
        feeds_into=["report"],
        confidence={Vuln.XSS: "medium", Vuln.DOM_XSS: "medium"},
        typical_duration_sec=120,
        rate_sensitive=True,
        noise_level="medium",
        notes="Use when dalfox fails — different fuzzing engine catches different bypasses.",
    ),

    "commix": ToolCapability(
        name="commix",
        category="vuln",
        description="Automated OS command injection exploiter. Tests all injection techniques "
                    "including classic, timing-based, and file-based.",
        detects=[Vuln.CMD_INJECTION, Vuln.CODE_INJECTION, Vuln.SSTI],
        inputs=[
            InputSpec("url", "url", True),
            InputSpec("data", "str", False, "POST body"),
        ],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["http", "crawl"],
        feeds_into=["report"],
        confidence={Vuln.CMD_INJECTION: "high", Vuln.CODE_INJECTION: "medium", Vuln.SSTI: "medium"},
        typical_duration_sec=180,
        rate_sensitive=True,
        noise_level="high",
        notes="Run after nuclei/manual triage identifies cmd injection candidates. "
              "Use --batch for non-interactive mode.",
    ),

    "wfuzz": ToolCapability(
        name="wfuzz",
        category="content",
        description="Web fuzzer for parameters, headers, and custom injection points.",
        detects=[Vuln.SQLI, Vuln.XSS, Vuln.SSRF, Vuln.CMD_INJECTION, Vuln.MISCONFIG],
        inputs=[InputSpec("url", "url", True), InputSpec("wordlist", "path", False)],
        outputs=[OutputField("results", "list[dict]")],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={Vuln.SQLI: "low", Vuln.XSS: "low"},
        typical_duration_sec=300,
        rate_sensitive=True,
        noise_level="high",
    ),

    # =========================================================================
    # SECRETS DISCOVERY
    # =========================================================================

    "trufflehog": ToolCapability(
        name="trufflehog",
        category="secrets",
        description="Scans filesystems, git repositories, S3 buckets, and Docker images "
                    "for secrets using entropy analysis and 700+ regex detectors.",
        detects=[Vuln.SECRET_EXPOSURE],
        inputs=[
            InputSpec("target", "path", True, "Path, git URL, S3 URI, or Docker image"),
            InputSpec("target_type", "str", False,
                      "filesystem|git|github|s3|gcs|docker (default: filesystem)"),
        ],
        outputs=[
            OutputField("secrets", "list[dict]",
                        "detector, verified, raw (truncated), source metadata"),
            OutputField("secrets_found", "int"),
        ],
        requires_phase=[],
        feeds_into=["report"],
        confidence={Vuln.SECRET_EXPOSURE: "high"},   # verified=True means API confirmed valid
        typical_duration_sec=120,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="verified=True means TruffleHog pinged the API endpoint and confirmed the key is active. "
              "Run on any JS files, recon output directory, and GitHub repos. "
              "Also run with 'github' type against the org's public repos.",
    ),

    "gitleaks": ToolCapability(
        name="gitleaks",
        category="secrets",
        description="Detects secrets in git history — including commits that were 'deleted' "
                    "but remain in git objects.",
        detects=[Vuln.SECRET_EXPOSURE],
        inputs=[
            InputSpec("target", "path", True, "Local git repository path"),
        ],
        outputs=[
            OutputField("secrets", "list[dict]",
                        "rule_id, file, line, secret (truncated), commit hash"),
            OutputField("secrets_found", "int"),
        ],
        requires_phase=[],
        feeds_into=["report"],
        confidence={Vuln.SECRET_EXPOSURE: "high"},
        typical_duration_sec=60,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Run on cloned git repos. Former developers often commit secrets that "
              "get removed in later commits but remain in git history.",
    ),

    # =========================================================================
    # API TESTING
    # =========================================================================

    "jwt_tool": ToolCapability(
        name="jwt_tool",
        category="api",
        description="JWT security testing toolkit. Tests alg:none, key confusion, "
                    "weak secret cracking, header injection (kid, jku, x5u), and claim forgery.",
        detects=[Vuln.JWT_ATTACK, Vuln.BROKEN_AUTH],
        inputs=[
            InputSpec("token", "str", True, "JWT token string"),
            InputSpec("mode", "str", False, "decode|crack|fuzz|algnone"),
        ],
        outputs=[
            OutputField("decoded", "dict", "Header, payload, signature"),
            OutputField("vulnerabilities", "list[str]"),
        ],
        requires_phase=["http"],
        feeds_into=["report"],
        confidence={Vuln.JWT_ATTACK: "high", Vuln.BROKEN_AUTH: "medium"},
        typical_duration_sec=30,
        rate_sensitive=False,
        noise_level="low",
        notes="Requires a captured JWT token. Run after extracting token from "
              "Burp/traffic. Alg:none and RS256→HS256 confusion are still common.",
    ),

    "kiterunner": ToolCapability(
        name="kiterunner",
        category="api",
        description="API endpoint discovery using smart wordlists based on real API schemas "
                    "(Swagger/OpenAPI). Much more accurate than generic directory brute-force.",
        detects=[Vuln.API_EXPOSURE, Vuln.BROKEN_AUTH, Vuln.INFO_LEAK],
        inputs=[
            InputSpec("target", "url", True, "Base API URL"),
            InputSpec("wordlist", "path", False, "API route wordlist"),
        ],
        outputs=[
            OutputField("endpoints", "list[str]", "Discovered API endpoints"),
            OutputField("count", "int"),
        ],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={Vuln.API_EXPOSURE: "high", Vuln.BROKEN_AUTH: "low"},
        typical_duration_sec=120,
        rate_sensitive=True,
        noise_level="medium",
        notes="Includes built-in wordlist of 23,000+ API routes from real APIs. "
              "Better than ffuf for REST API discovery.",
    ),

    "arjun": ToolCapability(
        name="arjun",
        category="api",
        description="HTTP parameter discovery tool. Finds hidden GET/POST parameters "
                    "using a smart request-minimization algorithm.",
        detects=[Vuln.PARAM_POLLUTION, Vuln.INFO_LEAK],
        inputs=[
            InputSpec("url", "url", True),
            InputSpec("method", "str", False, "GET|POST|JSON|XML (default: GET)"),
        ],
        outputs=[
            OutputField("parameters", "list[str]", "Discovered parameter names"),
        ],
        requires_phase=["http"],
        feeds_into=["vuln"],
        confidence={Vuln.PARAM_POLLUTION: "medium"},
        typical_duration_sec=60,
        rate_sensitive=True,
        noise_level="medium",
        notes="Run against every unique endpoint. Hidden parameters are a primary "
              "source of SSRF, SQLi, and IDOR findings in modern apps.",
    ),

    # =========================================================================
    # CLOUD
    # =========================================================================

    "s3scanner": ToolCapability(
        name="s3scanner",
        category="cloud",
        description="Enumerates and checks S3 buckets for public access, "
                    "world-readable/writable ACLs, and content listing.",
        detects=[Vuln.S3_MISCONFIG, Vuln.EXPOSED_FILES, Vuln.INFO_LEAK],
        inputs=[InputSpec("domain", "domain", True, "Company name or domain to derive bucket names")],
        outputs=[
            OutputField("buckets", "list[str]", "Found bucket names and their access level"),
        ],
        requires_phase=[],
        feeds_into=["report"],
        confidence={Vuln.S3_MISCONFIG: "high"},
        typical_duration_sec=60,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Generates bucket name guesses from company name. Also try company abbreviations, "
              "product names, and region variants.",
    ),

    "cloudbrute": ToolCapability(
        name="cloudbrute",
        category="cloud",
        description="Brute-forces cloud storage assets across AWS S3, GCP, and Azure "
                    "using keyword-based name generation.",
        detects=[Vuln.S3_MISCONFIG, Vuln.EXPOSED_FILES],
        inputs=[
            InputSpec("domain", "domain", True),
            InputSpec("keyword", "str", False, "Brand keyword for name generation"),
        ],
        outputs=[OutputField("found", "list[str]")],
        requires_phase=[],
        feeds_into=["report"],
        confidence={Vuln.S3_MISCONFIG: "high"},
        typical_duration_sec=120,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
    ),

    # =========================================================================
    # UTILITIES
    # =========================================================================

    "gf": ToolCapability(
        name="gf",
        category="util",
        description="Pattern-based URL classifier. Filters large URL lists into "
                    "vuln-class-specific candidates using regex patterns.",
        detects=[Vuln.SQLI, Vuln.XSS, Vuln.SSRF, Vuln.OPEN_REDIRECT, Vuln.LFI, Vuln.SSTI, Vuln.CODE_INJECTION],
        inputs=[
            InputSpec("urls", "list[str]", True, "URL list (stdin)"),
            InputSpec("pattern", "str", True, "Pattern name: sqli|xss|ssrf|redirect|rce|idor|lfi|ssti|debug"),
        ],
        outputs=[
            OutputField("matches", "list[str]", "URLs matching the vulnerability pattern"),
        ],
        requires_phase=["crawl"],
        feeds_into=["vuln"],
        confidence={Vuln.SQLI: "low", Vuln.XSS: "low", Vuln.SSRF: "low", Vuln.LFI: "low"},
        typical_duration_sec=5,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Essential triage tool. Dramatically reduces false positives by pre-filtering "
              "before expensive scanners. Use all patterns: sqli, xss, ssrf, redirect, rce, idor, lfi.",
    ),

    "qsreplace": ToolCapability(
        name="qsreplace",
        category="util",
        description="Replaces all query string values with a specified string (e.g., FUZZ). "
                    "Prepares URL lists for injection testing.",
        detects=[],
        inputs=[
            InputSpec("urls", "list[str]", True),
            InputSpec("replacement", "str", False, "Replacement value (default: FUZZ)"),
        ],
        outputs=[OutputField("urls", "list[str]", "URLs with all query values replaced")],
        requires_phase=["crawl"],
        feeds_into=["vuln"],
        confidence={},
        typical_duration_sec=2,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Use before piping into dalfox or sqlmap to test all parameters.",
    ),

    "anew": ToolCapability(
        name="anew",
        category="util",
        description="Deduplicates streaming output against a saved list. "
                    "Essential for incremental scanning sessions.",
        detects=[],
        inputs=[
            InputSpec("existing", "list[str]", True, "Existing items file"),
            InputSpec("new_items", "list[str]", True, "New items (stdin)"),
        ],
        outputs=[OutputField("new_items", "list[str]", "Only items not already in existing file")],
        requires_phase=[],
        feeds_into=[],
        confidence={},
        typical_duration_sec=1,
        rate_sensitive=False,
        noise_level="low",
        passive=True,
        notes="Use between every tool to avoid re-scanning already-seen assets.",
    ),

    # =========================================================================
    # OWASP WSTG v4.2 GAP CHECKS
    # =========================================================================

    "owasp_gap_weak_tls": ToolCapability(
        name="owasp_gap_weak_tls",
        category="crypto",
        description="Detects deprecated TLS versions (1.0/1.1) and weak cipher suites.",
        detects=[Vuln.WEAK_TLS, Vuln.TLS_CERT_ISSUE],
        inputs=[InputSpec("host", "host", True, "Target hostname")],
        outputs=[OutputField("findings", "list[dict]", "TLS weakness findings")],
        requires_phase=["deep_recon"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.WEAK_TLS: "high", Vuln.TLS_CERT_ISSUE: "high"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low", passive=False,
        notes="Uses stdlib ssl module — no external tools required.",
    ),
    "owasp_gap_backup_files": ToolCapability(
        name="owasp_gap_backup_files",
        category="config",
        description="Probes for backup/archive files (.bak, .old, .zip, .sql, etc.) in webroot.",
        detects=[Vuln.BACKUP_FILES, Vuln.INFO_LEAK],
        inputs=[InputSpec("base_url", "url", True), InputSpec("paths", "list[str]", False)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["deep_recon"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.BACKUP_FILES: "high"},
        typical_duration_sec=30, rate_sensitive=True, noise_level="medium",
        notes="Caps at 20 paths × 13 extensions = 260 requests max.",
    ),
    "owasp_gap_csrf": ToolCapability(
        name="owasp_gap_csrf",
        category="session",
        description="Detects missing CSRF token protection on state-changing endpoints.",
        detects=[Vuln.CSRF],
        inputs=[InputSpec("url", "url", True), InputSpec("body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.CSRF: "high"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_cookie_attrs": ToolCapability(
        name="owasp_gap_cookie_attrs",
        category="session",
        description="Checks Set-Cookie headers for missing HttpOnly, Secure, SameSite flags.",
        detects=[Vuln.COOKIE_ATTRS],
        inputs=[InputSpec("url", "url", True), InputSpec("headers", "dict", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=[],
        confidence={Vuln.COOKIE_ATTRS: "high"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_session_fixation": ToolCapability(
        name="owasp_gap_session_fixation",
        category="session",
        description="Compares session IDs before and after login to detect fixation.",
        detects=[Vuln.SESSION_FIXATION],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=[],
        confidence={Vuln.SESSION_FIXATION: "high"},
        typical_duration_sec=15, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_account_enum": ToolCapability(
        name="owasp_gap_account_enum",
        category="auth",
        description="Statistical timing comparison between valid and invalid usernames at login.",
        detects=[Vuln.ACCOUNT_ENUM],
        inputs=[InputSpec("login_url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=[],
        confidence={Vuln.ACCOUNT_ENUM: "medium"},
        typical_duration_sec=30, rate_sensitive=True, noise_level="medium",
        notes="Sends 20 login requests (10 valid, 10 invalid). May trigger lockout on aggressive targets.",
    ),
    "owasp_gap_ldap_injection": ToolCapability(
        name="owasp_gap_ldap_injection",
        category="injection",
        description="Detects LDAP injection via response differential on LDAP-backed auth endpoints.",
        detects=[Vuln.LDAP_INJECTION],
        inputs=[InputSpec("url", "url", True), InputSpec("param", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.LDAP_INJECTION: "high"},
        typical_duration_sec=20, rate_sensitive=False, noise_level="medium",
    ),
    "owasp_gap_mail_header_inj": ToolCapability(
        name="owasp_gap_mail_header_inj",
        category="injection",
        description="Detects mail header injection via CRLF in email form parameters.",
        detects=[Vuln.MAIL_HEADER_INJ],
        inputs=[InputSpec("url", "url", True), InputSpec("param", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.MAIL_HEADER_INJ: "medium"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_code_injection": ToolCapability(
        name="owasp_gap_code_injection",
        category="injection",
        description="Detects server-side code injection (PHP eval, Node exec, Python exec).",
        detects=[Vuln.CODE_INJECTION],
        inputs=[InputSpec("url", "url", True), InputSpec("param", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.CODE_INJECTION: "high"},
        typical_duration_sec=20, rate_sensitive=False, noise_level="high",
    ),
    "owasp_gap_csv_injection": ToolCapability(
        name="owasp_gap_csv_injection",
        category="injection",
        description="Detects CSV formula injection in data export endpoints.",
        detects=[Vuln.CSV_INJECTION],
        inputs=[InputSpec("url", "url", True), InputSpec("param", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.CSV_INJECTION: "medium"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_web_storage": ToolCapability(
        name="owasp_gap_web_storage",
        category="client_side",
        description="Detects sensitive data (tokens, passwords) stored in localStorage/sessionStorage.",
        detects=[Vuln.WEB_STORAGE],
        inputs=[InputSpec("url", "url", True), InputSpec("js_body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.WEB_STORAGE: "medium"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_postmessage": ToolCapability(
        name="owasp_gap_postmessage",
        category="client_side",
        description="Detects postMessage listeners without origin validation.",
        detects=[Vuln.POSTMESSAGE_HIJACK],
        inputs=[InputSpec("url", "url", True), InputSpec("js_body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.POSTMESSAGE_HIJACK: "medium"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_insecure_rng": ToolCapability(
        name="owasp_gap_insecure_rng",
        category="crypto",
        description="Chi-squared entropy analysis of session tokens to detect weak/predictable RNG.",
        detects=[Vuln.INSECURE_RNG],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.INSECURE_RNG: "medium"},
        typical_duration_sec=15, rate_sensitive=True, noise_level="low",
    ),
    "owasp_gap_weak_crypto": ToolCapability(
        name="owasp_gap_weak_crypto",
        category="crypto",
        description="Static analysis of JS/response bodies for MD5, SHA1, DES, AES-ECB, base64-as-crypto patterns.",
        detects=[Vuln.WEAK_CRYPTO],
        inputs=[InputSpec("url", "url", True), InputSpec("body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=[],
        confidence={Vuln.WEAK_CRYPTO: "medium"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_padding_oracle": ToolCapability(
        name="owasp_gap_padding_oracle",
        category="crypto",
        description="Detects padding oracle vulnerability by bit-flipping CBC-mode cookies.",
        detects=[Vuln.PADDING_ORACLE],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.PADDING_ORACLE: "high"},
        typical_duration_sec=20, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_service_worker": ToolCapability(
        name="owasp_gap_service_worker",
        category="client_side",
        description="Detects service worker registered at root scope — may intercept sensitive API calls.",
        detects=[Vuln.SERVICE_WORKER],
        inputs=[InputSpec("url", "url", True), InputSpec("js_body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=[],
        confidence={Vuln.SERVICE_WORKER: "low"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_webrtc": ToolCapability(
        name="owasp_gap_webrtc",
        category="client_side",
        description="Detects WebRTC API usage that may leak real IP through STUN/TURN.",
        detects=[Vuln.WEBRTC_LEAK],
        inputs=[InputSpec("url", "url", True), InputSpec("js_body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=[],
        confidence={Vuln.WEBRTC_LEAK: "low"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
        notes="Browser-based confirmation required for definitive result.",
    ),
    "owasp_gap_grpc_soap": ToolCapability(
        name="owasp_gap_grpc_soap",
        category="api",
        description="Detects exposed gRPC and SOAP/WSDL endpoints.",
        detects=[Vuln.GRPC_SOAP_EXPOSED],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.GRPC_SOAP_EXPOSED: "medium"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_saml": ToolCapability(
        name="owasp_gap_saml",
        category="auth",
        description="Detects unsigned SAML assertions vulnerable to forgery.",
        detects=[Vuln.SAML_VULN],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.SAML_VULN: "high"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_password_policy": ToolCapability(
        name="owasp_gap_password_policy",
        category="auth",
        description="Tests if application accepts weak passwords (1-char, 'password', '12345').",
        detects=[Vuln.WEAK_PASSWORD_POLICY],
        inputs=[InputSpec("register_url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=[],
        confidence={Vuln.WEAK_PASSWORD_POLICY: "high"},
        typical_duration_sec=20, rate_sensitive=True, noise_level="medium",
        notes="Creates temporary test accounts — cleans up if 'delete account' endpoint exists.",
    ),
}


# ── Query interface ───────────────────────────────────────────────────────────

class CapabilityMap:
    """Read-only interface for querying the capability database."""

    @staticmethod
    def get(tool_name: str) -> Optional[ToolCapability]:
        return CAPABILITIES.get(tool_name)

    @staticmethod
    def all_tools() -> list[str]:
        return sorted(CAPABILITIES.keys())

    @staticmethod
    def tools_for_vuln(vuln_class: str) -> list[tuple[str, str]]:
        """Return [(tool_name, confidence)] for tools that detect this vuln class."""
        results = []
        for name, cap in CAPABILITIES.items():
            if vuln_class in cap.detects:
                conf = cap.confidence.get(vuln_class, "low")
                results.append((name, conf))
        # Sort: high confidence first
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(results, key=lambda x: order.get(x[1], 3))

    @staticmethod
    def by_category(category: str) -> list[ToolCapability]:
        return [cap for cap in CAPABILITIES.values() if cap.category == category]

    @staticmethod
    def passive_tools() -> list[str]:
        return [name for name, cap in CAPABILITIES.items() if cap.passive]

    @staticmethod
    def tools_for_phase(phase: str) -> list[str]:
        """Tools that feed into a given phase (i.e., their output is needed by that phase)."""
        return [name for name, cap in CAPABILITIES.items() if phase in cap.feeds_into]

    @staticmethod
    def requires(tool_name: str) -> list[str]:
        """Phases that must complete before running this tool."""
        cap = CAPABILITIES.get(tool_name)
        return cap.requires_phase if cap else []

    @staticmethod
    def coverage_matrix() -> dict[str, list[str]]:
        """
        Returns a matrix: vuln_class → list of tools that detect it,
        sorted by confidence (high first).
        """
        matrix: dict[str, list[str]] = {}
        for vuln in vars(Vuln).values():
            if not isinstance(vuln, str):
                continue
            tools = CapabilityMap.tools_for_vuln(vuln)
            if tools:
                matrix[vuln] = [f"{t}({c[0]})" for t, c in tools]
        return matrix

    @staticmethod
    def print_coverage_matrix():
        """Pretty-print the full vulnerability coverage matrix."""
        matrix = CapabilityMap.coverage_matrix()
        print(f"\n{'─'*70}")
        print(f"  {'VULNERABILITY CLASS':<38} TOOLS (confidence)")
        print(f"{'─'*70}")
        for vuln, tools in sorted(matrix.items()):
            tool_str = ", ".join(tools)
            print(f"  {vuln:<38} {tool_str}")
        print(f"{'─'*70}\n")

    @staticmethod
    def optimal_order() -> list[str]:
        """
        Return tools in optimal execution order based on dependency graph.
        Phase ordering: passive → subdomain → dns → http → crawl/ports → content → api → vuln → secrets
        """
        return [
            # Phase 0: Passive (no target contact)
            "gauplus", "waybackurls", "paramspider",
            # Phase 1: Subdomain enumeration (passive)
            "assetfinder", "chaos", "findomain", "subfinder", "sublist3r", "amass",
            # Phase 2: DNS resolution + takeover check
            "dnsx",
            # Phase 3: HTTP probing — gate for all active phases
            "httpx",
            # Phase 4: Technology fingerprinting
            "whatweb",
            # Phase 5: Port scanning (parallel with crawl)
            "naabu", "rustscan", "masscan", "nmap",
            # Phase 6: Active crawling
            "hakrawler", "katana",
            # Phase 7: Content discovery
            "ffuf", "gobuster", "dirsearch", "wfuzz",
            # Phase 8: API discovery
            "kiterunner", "arjun",
            # Phase 9: URL triage (gf patterns)
            "gf", "qsreplace", "kxss",
            # Phase 10: Vulnerability scanning
            "crlfuzz", "dalfox", "sqlmap", "xssstrike", "commix", "nuclei", "nikto",
            # Phase 11: JWT / auth
            "jwt_tool",
            # Phase 12: Cloud
            "s3scanner", "cloudbrute",
            # Phase 13: Secrets
            "trufflehog", "gitleaks",
            # Utilities (run throughout)
            "anew",
        ]
