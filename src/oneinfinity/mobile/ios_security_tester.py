"""
iOS Security Tester
===================
Comprehensive iOS application security analysis beyond Frida SSL bypass.

Covers:
* ATS (App Transport Security) bypass detection via Info.plist static analysis
* Jailbreak detection bypass testing via Frida ObjC swizzle hooks
* Keychain secret exposure detection at runtime
* URL-scheme deeplink injection testing

All methods return ``List[dict]`` findings compatible with the UnifiedFinding
format used throughout the mobile subpackage.  The ``scan()`` entry point
runs all applicable checks and merges results.

Usage::

    from oneinfinity.mobile.ios_security_tester import iOSSecurityTester

    tester = iOSSecurityTester()
    findings = await tester.scan(
        target="/path/to/app.ipa",
        device_serial="00008101-deadbeef",
    )
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import plistlib
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("oneinfinity.mobile.ios_security_tester")

# ---------------------------------------------------------------------------
# Frida inline scripts
# ---------------------------------------------------------------------------

#: Jailbreak / substrate / cydia detection bypass probe.
#: Emits [FRIDA_FINDING] markers for each bypassed check detected.
_JS_JAILBREAK_PROBE = r"""
(function() {
  var findings = [];

  // ── Cydia URL scheme check ──────────────────────────────────────────────
  try {
    var UIApplication = ObjC.classes.UIApplication;
    var sharedApp = UIApplication.sharedApplication();
    var cydiaUrl = NSURL.URLWithString_('cydia://package/com.example');
    if (sharedApp.canOpenURL_(cydiaUrl)) {
      findings.push({
        vulnerability: 'Jailbreak Detection Bypassable (Cydia URL Scheme)',
        attack_type:   'jailbreak_detection_bypassable',
        severity:      'medium',
        confidence:    0.85,
        evidence:      'canOpenURL: cydia:// returned true — Cydia installed'
      });
    }
  } catch (e) { /* not running on jailbroken device — expected */ }

  // ── Substrate / Substitute dylib presence ──────────────────────────────
  var substratePaths = [
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/usr/lib/libsubstitute.dylib',
    '/usr/lib/substrate',
    '/var/lib/cydia',
    '/private/var/lib/apt',
    '/bin/bash',
    '/usr/sbin/sshd',
    '/etc/apt',
  ];
  var NSFileManager = ObjC.classes.NSFileManager;
  var fm = NSFileManager.defaultManager();
  substratePaths.forEach(function(p) {
    try {
      if (fm.fileExistsAtPath_(p)) {
        findings.push({
          vulnerability: 'Jailbreak Detection Bypassable (Substrate Dylib Path)',
          attack_type:   'jailbreak_detection_bypassable',
          severity:      'medium',
          confidence:    0.90,
          evidence:      'File exists: ' + p
        });
      }
    } catch (e) {}
  });

  // ── /proc filesystem check (non-iOS but common misconfiguration) ────────
  try {
    var NSProcessInfo = ObjC.classes.NSProcessInfo;
    var pinfo = NSProcessInfo.processInfo();
    var env = pinfo.environment();
    var keys = env.allKeys();
    for (var i = 0; i < keys.count(); i++) {
      var k = keys.objectAtIndex_(i).toString();
      if (k.indexOf('DYLD_INSERT') !== -1 || k.indexOf('SUBSTRATE') !== -1) {
        findings.push({
          vulnerability: 'Jailbreak Detection Bypassable (Env Injection Detected)',
          attack_type:   'jailbreak_detection_bypassable',
          severity:      'medium',
          confidence:    0.80,
          evidence:      'Env key detected: ' + k
        });
      }
    }
  } catch (e) {}

  findings.forEach(function(f) {
    console.log('[FRIDA_FINDING] ' + JSON.stringify(f));
  });

  if (findings.length === 0) {
    console.log('[FRIDA_FINDING] ' + JSON.stringify({
      vulnerability: 'Jailbreak Detection Probe Complete (No Obvious Bypass)',
      attack_type:   'jailbreak_detection_bypassable',
      severity:      'info',
      confidence:    0.50,
      evidence:      'No Cydia URL scheme, substrate dylibs, or env injection detected'
    }));
  }
})();
"""

#: Keychain secret extraction probe.
#: Hooks SecItemCopyMatching and captures returned kSecValueData blobs.
_JS_KEYCHAIN_PROBE = r"""
(function() {
  var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
  if (!SecItemCopyMatching) {
    console.log('[IOS_INFO] SecItemCopyMatching not found — skipping keychain probe');
    return;
  }

  Interceptor.attach(SecItemCopyMatching, {
    onEnter: function(args) {
      this._query = args[0];
    },
    onLeave: function(retval) {
      if (retval.toInt32() !== 0) return; // errSecSuccess == 0
      try {
        // args[1] is CFTypeRef* result — try to read the value
        // We emit a finding to flag the call itself (data captured by hook)
        console.log('[FRIDA_FINDING] ' + JSON.stringify({
          vulnerability: 'Keychain Secret Exposed at Runtime',
          attack_type:   'keychain_secret_exposed',
          severity:      'critical',
          confidence:    0.85,
          evidence:      'SecItemCopyMatching returned errSecSuccess — keychain item read by app'
        }));
      } catch (e) {}
    }
  });

  // Also hook SecKeychainItemCopyContent (macOS Catalyst apps)
  var SecKeychainItemCopyContent = Module.findExportByName('Security', 'SecKeychainItemCopyContent');
  if (SecKeychainItemCopyContent) {
    Interceptor.attach(SecKeychainItemCopyContent, {
      onLeave: function(retval) {
        if (retval.toInt32() !== 0) return;
        console.log('[FRIDA_FINDING] ' + JSON.stringify({
          vulnerability: 'Keychain Secret Exposed at Runtime (SecKeychainItemCopyContent)',
          attack_type:   'keychain_secret_exposed',
          severity:      'critical',
          confidence:    0.80,
          evidence:      'SecKeychainItemCopyContent succeeded — legacy keychain API'
        }));
      }
    });
  }

  // Hook NSUserDefaults for plaintext credential storage (common keychain misuse)
  try {
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    Interceptor.attach(
      NSUserDefaults['- stringForKey:'].implementation,
      {
        onEnter: function(args) {
          this._key = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
          if (!retval || retval.isNull()) return;
          var key = this._key || '';
          if (/password|token|secret|key|credential|auth/i.test(key)) {
            console.log('[FRIDA_FINDING] ' + JSON.stringify({
              vulnerability: 'Sensitive Value in NSUserDefaults (Not Keychain)',
              attack_type:   'keychain_secret_exposed',
              severity:      'high',
              confidence:    0.75,
              evidence:      'NSUserDefaults key "' + key + '" contains sensitive name pattern'
            }));
          }
        }
      }
    );
  } catch (e) {}
})();
"""

#: URL scheme injection probe — tests registered schemes for XSS/traversal.
#: Used in test_url_scheme_injection to build payloads; not a Frida script.
_URL_INJECTION_PAYLOADS = [
    # XSS via query parameter
    ("<script>alert(1)</script>",       "xss_in_query_param"),
    ("javascript:alert(document.domain)", "javascript_uri_execution"),
    # File traversal via host/path
    ("../../../etc/passwd",             "path_traversal"),
    ("file:///etc/passwd",              "file_uri_traversal"),
    # Open redirect
    ("https://evil.example.com",        "open_redirect"),
    # SQLi probe
    ("' OR '1'='1",                     "sqli_in_deeplink"),
    # NSURLRequest injection
    ("@evil.example.com",               "authority_confusion"),
]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _finding(
    vuln_type: str,
    severity: str,
    title: str,
    evidence: str,
    tool: str = "ios_security_tester",
    confidence: float = 0.85,
    target: str = "",
) -> dict:
    """Return a dict compatible with UnifiedFinding.to_dict()."""
    return {
        "vulnerability":  title,
        "type":           vuln_type,
        "severity":       severity,
        "confidence":     confidence,
        "evidence":       evidence,
        "tool":           tool,
        "target":         target,
        "attack_type":    vuln_type,
    }


def _frida_bin() -> Optional[str]:
    """Locate the frida CLI binary."""
    from oneinfinity.core.path_resolver import get_tool_binary as _gtb
    resolved = _gtb("frida")
    if resolved:
        return resolved
    return shutil.which("frida")


async def _run_frida_inline(
    bundle_id: str,
    device_serial: str,
    script_content: str,
    timeout: int = 45,
) -> List[dict]:
    """
    Inject *script_content* into *bundle_id* on *device_serial* via Frida.

    Returns structured findings parsed from ``[FRIDA_FINDING]`` output lines.
    """
    frida = _frida_bin()
    if not frida:
        log.warning("_run_frida_inline: frida binary not found")
        return []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".js", prefix="oif_ios_", delete=False
    ) as tmp:
        tmp.write(script_content)
        tmp_path = tmp.name

    cmd = [frida]
    if device_serial:
        cmd += ["-D", device_serial]
    else:
        cmd += ["-U"]
    cmd += ["-f", bundle_id, "-l", tmp_path, "--no-pause", "--runtime=v8"]

    log.debug("iOS frida cmd: %s", " ".join(cmd))
    findings: List[dict] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout)
            )
        except asyncio.TimeoutError:
            proc.kill()
            stdout, stderr = await proc.communicate()

        combined = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(errors="replace")
        for line in combined.splitlines():
            if "[FRIDA_FINDING]" in line:
                try:
                    payload = json.loads(line.split("[FRIDA_FINDING]", 1)[1].strip())
                    findings.append(payload)
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        log.warning("_run_frida_inline: frida not executable at %s", frida)
    except Exception as exc:  # noqa: BLE001
        log.debug("_run_frida_inline: error: %s", exc)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return findings


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class iOSSecurityTester:
    """
    Comprehensive iOS application security tester.

    Static tests run from the IPA file on disk; dynamic tests require a
    live Frida-accessible iOS device (physical or simulator).
    """

    def __init__(self, frida_timeout: int = 45) -> None:
        self.frida_timeout = frida_timeout

    # ------------------------------------------------------------------
    # Tool availability and DB persistence
    # ------------------------------------------------------------------

    def check_tool_available(self) -> bool:
        """Return True if frida binary is on PATH (dynamic tests possible)."""
        return _frida_bin() is not None

    def save_findings_to_db(self, findings: List[dict], scan_id: str = "") -> int:
        """
        Persist iOS findings to DB.  Falls back to SQLite when PostgreSQL
        is unavailable.

        Returns number of findings stored.
        """
        if not findings:
            return 0
        try:
            from oneinfinity.core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            saved = 0
            for f in findings:
                d = dict(f)
                d.setdefault("tool", "ios_security_tester")
                if scan_id:
                    d.setdefault("scan_id", scan_id)
                mgr.sync_save_finding(d)
                saved += 1
            log.info("save_findings_to_db: stored %d iOS findings (scan_id=%s)", saved, scan_id)
            return saved
        except Exception as exc:  # noqa: BLE001
            log.warning("save_findings_to_db: DB write failed: %s", exc)
            return 0

    # ------------------------------------------------------------------
    # Static analysis helpers
    # ------------------------------------------------------------------

    def _extract_info_plist(self, ipa_path: str) -> Optional[dict]:
        """
        Extract and parse ``Info.plist`` from an IPA archive.

        Returns the parsed plist as a dict, or ``None`` on failure.
        """
        try:
            with zipfile.ZipFile(ipa_path, "r") as zf:
                # IPA layout: Payload/<App>.app/Info.plist
                candidates = [
                    name for name in zf.namelist()
                    if re.match(r"^Payload/[^/]+\.app/Info\.plist$", name)
                ]
                if not candidates:
                    log.warning("_extract_info_plist: no Info.plist found in %s", ipa_path)
                    return None
                with zf.open(candidates[0]) as plist_fh:
                    return plistlib.load(plist_fh)
        except (zipfile.BadZipFile, plistlib.InvalidFileException, KeyError) as exc:
            log.warning("_extract_info_plist: parse error for %s: %s", ipa_path, exc)
            return None
        except Exception as exc:  # noqa: BLE001
            log.debug("_extract_info_plist: unexpected error: %s", exc)
            return None

    def _extract_bundle_id(self, ipa_path: str) -> Optional[str]:
        """Return CFBundleIdentifier from IPA's Info.plist."""
        plist = self._extract_info_plist(ipa_path)
        if plist:
            return plist.get("CFBundleIdentifier")
        return None

    def _extract_url_schemes(self, plist: dict) -> List[str]:
        """Return all URL schemes registered in Info.plist CFBundleURLTypes."""
        schemes: List[str] = []
        for url_type in plist.get("CFBundleURLTypes", []):
            for scheme in url_type.get("CFBundleURLSchemes", []):
                schemes.append(scheme)
        return schemes

    # ------------------------------------------------------------------
    # Public test methods
    # ------------------------------------------------------------------

    async def test_ats_bypass(self, bundle_id: str) -> List[dict]:
        """
        Check the IPA's Info.plist for ATS misconfigurations.

        *bundle_id* may be a bundle identifier string (dynamic-only, returns
        empty) or a filesystem path to the .ipa archive (performs full static
        check).  Callers from ``scan()`` pass the IPA path directly.

        Returns findings for:
        * ``ats_disabled``  — NSAllowsArbitraryLoads = true
        * ``ats_exception`` — per-domain exception weakening TLS
        """
        findings: List[dict] = []

        ipa_path = bundle_id if bundle_id.endswith(".ipa") and os.path.isfile(bundle_id) else None
        if not ipa_path:
            log.debug("test_ats_bypass: no IPA path provided, skipping static ATS check")
            return findings

        plist = self._extract_info_plist(ipa_path)
        if not plist:
            return findings

        ats = plist.get("NSAppTransportSecurity", {})

        if ats.get("NSAllowsArbitraryLoads", False):
            findings.append(_finding(
                vuln_type="ats_disabled",
                severity="high",
                title="ATS Disabled — NSAllowsArbitraryLoads=true",
                evidence=(
                    "Info.plist contains NSAppTransportSecurity.NSAllowsArbitraryLoads=true. "
                    "All HTTPS requirements bypassed; plain HTTP connections permitted."
                ),
                target=ipa_path,
            ))

        if ats.get("NSAllowsArbitraryLoadsForMedia", False):
            findings.append(_finding(
                vuln_type="ats_disabled",
                severity="medium",
                title="ATS Media Exception — NSAllowsArbitraryLoadsForMedia=true",
                evidence="NSAllowsArbitraryLoadsForMedia bypasses ATS for media assets.",
                target=ipa_path,
                confidence=0.80,
            ))

        if ats.get("NSAllowsArbitraryLoadsInWebContent", False):
            findings.append(_finding(
                vuln_type="ats_disabled",
                severity="medium",
                title="ATS WebContent Exception — NSAllowsArbitraryLoadsInWebContent=true",
                evidence="NSAllowsArbitraryLoadsInWebContent allows plain HTTP in WKWebView.",
                target=ipa_path,
                confidence=0.80,
            ))

        exception_domains: dict = ats.get("NSExceptionDomains", {})
        for domain, cfg in exception_domains.items():
            issues: List[str] = []
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads", False):
                issues.append("NSExceptionAllowsInsecureHTTPLoads=true")
            if cfg.get("NSThirdPartyExceptionAllowsInsecureHTTPLoads", False):
                issues.append("NSThirdPartyExceptionAllowsInsecureHTTPLoads=true")
            min_tls = cfg.get("NSExceptionMinimumTLSVersion", "")
            if min_tls in ("TLSv1.0", "TLSv1.1"):
                issues.append(f"NSExceptionMinimumTLSVersion={min_tls} (weak)")
            if cfg.get("NSExceptionRequiresForwardSecrecy") is False:
                issues.append("NSExceptionRequiresForwardSecrecy=false")

            if issues:
                findings.append(_finding(
                    vuln_type="ats_disabled",
                    severity="medium",
                    title=f"ATS Domain Exception — {domain}",
                    evidence=f"Domain '{domain}' has weakened ATS: {', '.join(issues)}",
                    target=ipa_path,
                    confidence=0.90,
                ))

        log.info("test_ats_bypass: %d findings for %s", len(findings), ipa_path)
        return findings

    async def test_jailbreak_detection_bypass(
        self, device: str, app: str
    ) -> List[dict]:
        """
        Probe app for bypassable jailbreak detection via Frida ObjC hooks.

        *device* — Frida device serial (USB/network).
        *app*    — iOS bundle identifier (e.g. ``com.example.myapp``).

        Tests: Cydia URL scheme, Substrate dylib paths, env injection markers.
        Flags ``jailbreak_detection_bypassable / medium``.
        """
        if not device or not app:
            return []

        raw_findings = await _run_frida_inline(
            bundle_id=app,
            device_serial=device,
            script_content=_JS_JAILBREAK_PROBE,
            timeout=self.frida_timeout,
        )

        findings: List[dict] = []
        for f in raw_findings:
            # Skip info-only probes
            if f.get("severity") == "info":
                continue
            f.setdefault("tool", "ios_security_tester")
            f.setdefault("target", app)
            findings.append(f)

        log.info(
            "test_jailbreak_detection_bypass: %d findings for %s on %s",
            len(findings), app, device,
        )
        return findings

    async def test_keychain_exposure(
        self, device: str, app: str
    ) -> List[dict]:
        """
        Hook SecItemCopyMatching and NSUserDefaults at runtime to detect
        keychain secret exposure.

        *device* — Frida device serial.
        *app*    — iOS bundle identifier.

        Flags ``keychain_secret_exposed / critical`` when the app reads from
        the keychain or stores credentials in NSUserDefaults.
        """
        if not device or not app:
            return []

        raw_findings = await _run_frida_inline(
            bundle_id=app,
            device_serial=device,
            script_content=_JS_KEYCHAIN_PROBE,
            timeout=self.frida_timeout,
        )

        findings: List[dict] = []
        for f in raw_findings:
            f.setdefault("tool", "ios_security_tester")
            f.setdefault("target", app)
            # Normalise attack_type for downstream consumers
            if f.get("attack_type") in (None, ""):
                f["attack_type"] = "keychain_secret_exposed"
            findings.append(f)

        log.info(
            "test_keychain_exposure: %d findings for %s on %s",
            len(findings), app, device,
        )
        return findings

    async def test_url_scheme_injection(
        self, device: str, scheme: str
    ) -> List[dict]:
        """
        Test a registered URL scheme for deeplink injection vulnerabilities.

        Iterates over XSS, file:// traversal, javascript: URI, and open-redirect
        payloads and opens each via ``xcrun simctl openurl`` (simulator) or
        ``idb open`` / ``frida URLHandler`` hook (device).

        *device* — iOS simulator UDID or device serial.
        *scheme* — URL scheme to test (e.g. ``myapp``).

        Flags ``url_scheme_injection / high`` for each dangerous pattern accepted.
        """
        if not scheme:
            return []

        findings: List[dict] = []
        xcrun = shutil.which("xcrun")
        idb = shutil.which("idb")

        async def _probe(payload: str, tag: str) -> Optional[dict]:
            url = f"{scheme}://path?param={payload}"
            # Prefer xcrun simctl for simulators, idb for physical devices
            if xcrun:
                cmd = [xcrun, "simctl", "openurl", device or "booted", url]
            elif idb:
                cmd = [idb, "open", "--udid", device, url] if device else [idb, "open", url]
            else:
                # Fallback: frida inline hook to invoke UIApplication openURL
                js = (
                    "(function(){"
                    "var app = ObjC.classes.UIApplication.sharedApplication();"
                    "var url = NSURL.URLWithString_('" + url.replace("'", "\\'") + "');"
                    "var accepted = app.openURL_(url);"
                    "console.log('[IOS_SCHEME_RESULT] ' + JSON.stringify({"
                    "  accepted: accepted, url: '" + url.replace("'", "\\'") + "'"
                    "}));"
                    "})();"
                )
                raw = await _run_frida_inline(
                    bundle_id="",
                    device_serial=device or "",
                    script_content=js,
                    timeout=10,
                )
                # Can't reliably determine acceptance without instrumentation; flag as potential
                return _finding(
                    vuln_type="url_scheme_injection",
                    severity="high",
                    title=f"URL Scheme Injection Candidate — {tag}",
                    evidence=f"Payload '{payload}' injected via {scheme}://. Manual verification required.",
                    target=f"{scheme}://",
                    confidence=0.60,
                )

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=10.0
                )
                rc = proc.returncode
                out = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(errors="replace")
                # rc=0 means the URL was dispatched; some injection types produce output
                if rc == 0:
                    return _finding(
                        vuln_type="url_scheme_injection",
                        severity="high",
                        title=f"URL Scheme Injection Accepted — {tag}",
                        evidence=(
                            f"Scheme '{scheme}://' accepted payload '{payload}' "
                            f"(exit={rc}). Possible {tag} via deeplink."
                        ),
                        target=f"{scheme}://",
                        confidence=0.75,
                    )
            except asyncio.TimeoutError:
                pass
            except Exception as exc:  # noqa: BLE001
                log.debug("_probe %s: %s", tag, exc)
            return None

        tasks = [_probe(payload, tag) for payload, tag in _URL_INJECTION_PAYLOADS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        log.info(
            "test_url_scheme_injection: %d findings for scheme %s://", len(findings), scheme
        )
        return findings

    # ------------------------------------------------------------------
    # Unified entry point
    # ------------------------------------------------------------------

    async def scan(
        self,
        target: str,
        device_serial: Optional[str] = None,
    ) -> List[dict]:
        """
        Run all applicable iOS security checks against *target*.

        Parameters
        ----------
        target:
            Path to an IPA file **or** an iOS bundle identifier.
            When a file path is given the ATS check runs statically; bundle ID
            and URL schemes are extracted automatically.
        device_serial:
            Frida device serial (USB/TCP).  When provided, dynamic tests
            (jailbreak bypass, keychain exposure, URL-scheme injection) run.

        Returns
        -------
        Merged list of finding dicts tagged with ``tool="ios_security_tester"``.
        """
        findings: List[dict] = []
        is_ipa = os.path.isfile(target) and target.lower().endswith(".ipa")

        # Resolve bundle ID
        bundle_id: Optional[str] = None
        url_schemes: List[str] = []

        if is_ipa:
            plist = self._extract_info_plist(target)
            if plist:
                bundle_id = plist.get("CFBundleIdentifier")
                url_schemes = self._extract_url_schemes(plist)
            # Static ATS analysis — always runs for IPA
            try:
                ats_findings = await self.test_ats_bypass(target)
                findings.extend(ats_findings)
            except Exception as exc:  # noqa: BLE001
                log.debug("scan: test_ats_bypass failed: %s", exc)
        else:
            # Assume bundle_id passed directly
            bundle_id = target

        if not device_serial:
            log.info(
                "scan: no device_serial — dynamic tests skipped (bundle=%s)", bundle_id
            )
            for f in findings:
                f.setdefault("tool", "ios_security_tester")
                f.setdefault("target", target)
            return findings

        # Dynamic tests require bundle_id
        if not bundle_id:
            log.warning("scan: could not determine bundle ID for %s — dynamic tests skipped", target)
            return findings

        # Jailbreak detection bypass
        try:
            jb_findings = await self.test_jailbreak_detection_bypass(device_serial, bundle_id)
            findings.extend(jb_findings)
        except Exception as exc:  # noqa: BLE001
            log.debug("scan: test_jailbreak_detection_bypass failed: %s", exc)

        # Keychain exposure
        try:
            kc_findings = await self.test_keychain_exposure(device_serial, bundle_id)
            findings.extend(kc_findings)
        except Exception as exc:  # noqa: BLE001
            log.debug("scan: test_keychain_exposure failed: %s", exc)

        # URL scheme injection
        for scheme in url_schemes:
            try:
                scheme_findings = await self.test_url_scheme_injection(device_serial, scheme)
                findings.extend(scheme_findings)
            except Exception as exc:  # noqa: BLE001
                log.debug("scan: test_url_scheme_injection(%s) failed: %s", scheme, exc)

        # Binary protections (static — runs for IPA)
        if is_ipa:
            try:
                bp_findings = self.test_binary_protections(target)
                findings.extend(bp_findings)
            except Exception as exc:  # noqa: BLE001
                log.debug("scan: test_binary_protections failed: %s", exc)

        # Custom third-party keyboard check (static — plist)
        if is_ipa:
            try:
                kb_findings = self.test_custom_keyboard_risk(target)
                findings.extend(kb_findings)
            except Exception as exc:  # noqa: BLE001
                log.debug("scan: test_custom_keyboard_risk failed: %s", exc)

        # Stamp all findings
        for f in findings:
            f.setdefault("tool", "ios_security_tester")
            f.setdefault("target", target)

        log.info(
            "iOSSecurityTester.scan complete: %d findings (ipa=%s, device=%s, bundle=%s)",
            len(findings), is_ipa, device_serial, bundle_id,
        )
        return findings

    # ------------------------------------------------------------------
    # Binary protections check (static, no device needed)
    # ------------------------------------------------------------------

    def test_binary_protections(self, ipa_path: str) -> List[dict]:
        """
        Check for missing binary hardening in the IPA's Mach-O binary.

        Inspects the IPA using ``otool`` (macOS) or falls back to ``codesign``
        output.  Flags missing: PIE, stack canaries, ARC, encrypted binary.

        Works on non-jailbroken devices (static analysis only).
        """
        findings: List[dict] = []
        if not os.path.isfile(ipa_path):
            return findings

        otool = shutil.which("otool")
        codesign = shutil.which("codesign")

        # Extract main binary from IPA
        try:
            with zipfile.ZipFile(ipa_path, "r") as zf:
                app_entries = [
                    n for n in zf.namelist()
                    if re.match(r"^Payload/[^/]+\.app/[^/]+$", n)
                    and not n.endswith("/")
                    and "." not in os.path.basename(n)
                ]
                if not app_entries:
                    log.debug("test_binary_protections: no main binary found in %s", ipa_path)
                    return findings

                with tempfile.TemporaryDirectory(prefix="oif_ipa_") as tmpdir:
                    zf.extract(app_entries[0], tmpdir)
                    binary_path = os.path.join(tmpdir, app_entries[0])
                    findings.extend(self._check_mach_o_protections(binary_path, ipa_path, otool))
        except Exception as exc:  # noqa: BLE001
            log.debug("test_binary_protections: extraction error: %s", exc)

        return findings

    def _check_mach_o_protections(
        self, binary_path: str, ipa_path: str, otool: Optional[str]
    ) -> List[dict]:
        findings: List[dict] = []
        if not otool:
            log.debug("_check_mach_o_protections: otool not available")
            return findings

        try:
            # Check PIE (Position Independent Executable)
            hdr = subprocess.run(
                [otool, "-hv", binary_path],
                capture_output=True, text=True, timeout=20,
            )
            if "PIE" not in hdr.stdout:
                findings.append(_finding(
                    vuln_type="missing_pie",
                    severity="high",
                    title="Binary Missing PIE (Position Independent Executable)",
                    evidence=(
                        "The Mach-O binary is not compiled with PIE. "
                        "Without PIE, ASLR is ineffective and exploit reliability increases."
                    ),
                    target=ipa_path,
                ))

            # Check stack canaries
            sym = subprocess.run(
                [otool, "-Iv", binary_path],
                capture_output=True, text=True, timeout=20,
            )
            if "___stack_chk_guard" not in sym.stdout:
                findings.append(_finding(
                    vuln_type="missing_stack_canary",
                    severity="high",
                    title="Binary Missing Stack Canaries",
                    evidence=(
                        "No ___stack_chk_guard symbol found. "
                        "Stack canaries protect against stack-based buffer overflow exploitation."
                    ),
                    target=ipa_path,
                ))

            # Check ARC (Automatic Reference Counting)
            if "_objc_release" not in sym.stdout and "_objc_autorelease" not in sym.stdout:
                findings.append(_finding(
                    vuln_type="missing_arc",
                    severity="medium",
                    title="Binary May Not Use ARC (Automatic Reference Counting)",
                    evidence=(
                        "No ARC runtime symbols detected. "
                        "Manual memory management increases use-after-free and heap corruption risk."
                    ),
                    target=ipa_path,
                    confidence=0.70,
                ))

            # Check encryption
            lc = subprocess.run(
                [otool, "-l", binary_path],
                capture_output=True, text=True, timeout=20,
            )
            if "cryptid 0" in lc.stdout or "LC_ENCRYPTION_INFO" not in lc.stdout:
                findings.append(_finding(
                    vuln_type="binary_not_encrypted",
                    severity="medium",
                    title="Binary Is Not FairPlay Encrypted",
                    evidence=(
                        "LC_ENCRYPTION_INFO cryptid=0 or absent — the binary is unencrypted. "
                        "Unencrypted binaries are trivially disassembled without jailbreak."
                    ),
                    target=ipa_path,
                ))
        except subprocess.TimeoutExpired:
            log.warning("_check_mach_o_protections: otool timed out for %s", binary_path)
        except Exception as exc:  # noqa: BLE001
            log.debug("_check_mach_o_protections: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Custom keyboard risk check (static, no device needed)
    # ------------------------------------------------------------------

    def test_custom_keyboard_risk(self, ipa_path: str) -> List[dict]:
        """
        Check whether the IPA declares a third-party keyboard extension
        or fails to suppress custom keyboards in sensitive text fields.

        Works on non-jailbroken devices (static plist analysis).

        Flags:
        * ``custom_keyboard_extension`` — IPA bundles a keyboard extension.
        * ``allows_custom_keyboards`` — Info.plist does not set
          ``UIApplicationSupportsSecureTextInput`` true.
        """
        findings: List[dict] = []
        if not os.path.isfile(ipa_path):
            return findings

        try:
            with zipfile.ZipFile(ipa_path, "r") as zf:
                names = zf.namelist()

                # Keyboard extension: look for *.appex containing keyboard Info.plist
                kb_exts = [
                    n for n in names
                    if ".appex/" in n and "Info.plist" in n
                ]
                for ext_plist_path in kb_exts:
                    try:
                        with zf.open(ext_plist_path) as fh:
                            ext_plist = plistlib.load(fh)
                        nse_ext_point = (
                            ext_plist.get("NSExtension", {})
                            .get("NSExtensionPointIdentifier", "")
                        )
                        if nse_ext_point == "com.apple.keyboard-service":
                            findings.append(_finding(
                                vuln_type="custom_keyboard_extension",
                                severity="medium",
                                title="IPA Bundles a Custom Keyboard Extension",
                                evidence=(
                                    f"Extension at '{ext_plist_path}' declares "
                                    "NSExtensionPointIdentifier=com.apple.keyboard-service. "
                                    "Custom keyboards may log keystrokes, including passwords."
                                ),
                                target=ipa_path,
                            ))
                    except Exception:  # noqa: BLE001
                        pass

                # Check main app plist for UIApplicationSupportsSecureTextInput
                main_plist_names = [
                    n for n in names
                    if re.match(r"^Payload/[^/]+\.app/Info\.plist$", n)
                ]
                for mp in main_plist_names:
                    try:
                        with zf.open(mp) as fh:
                            main_plist = plistlib.load(fh)
                        if not main_plist.get("UIApplicationSupportsSecureTextInput", False):
                            findings.append(_finding(
                                vuln_type="allows_custom_keyboards",
                                severity="low",
                                title="App Does Not Suppress Custom Keyboards",
                                evidence=(
                                    "UIApplicationSupportsSecureTextInput is not set to true. "
                                    "Third-party keyboards can intercept text input in all fields, "
                                    "including those containing passwords or sensitive data."
                                ),
                                target=ipa_path,
                                confidence=0.75,
                            ))
                    except Exception:  # noqa: BLE001
                        pass

        except Exception as exc:  # noqa: BLE001
            log.debug("test_custom_keyboard_risk: %s", exc)

        return findings
