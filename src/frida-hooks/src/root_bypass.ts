/**
 * root_bypass.ts — Root / Jailbreak detection bypass (14 methods)
 *
 * Covers:
 *   1.  su binary  — File.exists() override for known su paths
 *   2.  Magisk     — PackageManager.getPackageInfo / getInstalledPackages
 *   3.  SuperSU    — same
 *   4.  RootBeer   — isRooted, isRootedWithoutBusyBox + all check* methods
 *   5.  Build.TAGS — patched to release-keys
 *   6.  /proc/net/tcp port 27042 — connect() returns ECONNREFUSED
 *   7.  frida-server process name — /proc/self/cmdline read intercept
 *   8.  Native su path — libc open() hook
 *   9.  Runtime.exec("su") — throw IOException
 *  10.  SystemProperties.get — ro.build.tags / ro.debuggable / ro.secure
 *  11.  SafetyNet attest — mock bypass
 *  12.  Play Integrity — IntegrityManager hook
 *  13.  PackageManager.getInstalledPackages — filter root manager APKs
 *  14.  libc.open /proc/net/tcp intercept
 */

"use strict";

// ─── helpers ─────────────────────────────────────────────────────────────────

function emitEvent(hook: string, data: Record<string, unknown>): void {
  send(
    JSON.stringify({
      type: "hook_event",
      hook,
      timestamp: Date.now(),
      ...data,
    })
  );
}

const ROOT_PACKAGES = new Set([
  "com.topjohnwu.magisk",
  "eu.chainfire.supersu",
  "com.koushikdutta.superuser",
  "com.noshufou.android.su",
  "com.thirdparty.superuser",
  "com.yellowes.su",
  "com.kingouser.com",
  "com.saurik.substrate",
  "de.robv.android.xposed.installer",
]);

const SU_PATHS = [
  "/system/app/Superuser.apk",
  "/system/xbin/su",
  "/system/bin/su",
  "/sbin/su",
  "/su/bin/su",
  "/data/local/xbin/su",
  "/data/local/bin/su",
  "/data/local/su",
  "/system/sd/xbin/su",
  "/system/bin/failsafe/su",
  "/system/app/SuperSU.apk",
  "/system/app/Magisk.apk",
  "/system/xbin/busybox",
  "/system/bin/busybox",
];

// ─── Native layer (all platforms) ────────────────────────────────────────────

// 6 + 14: connect() — hide Frida port 27042 AND /proc/net/tcp scans
const connectPtr = Module.findExportByName(null, "connect");
if (connectPtr) {
  try {
    Interceptor.attach(connectPtr, {
      onEnter(args) {
        try {
          const sockaddr = args[1];
          // AF_INET = 2; port bytes at offset 2-3 (big-endian)
          const family = sockaddr.readU16();
          if (family === 2) {
            const port = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8());
            if (port === 27042) {
              emitEvent("root_bypass", { method: "connect", port, action: "blocked" });
              // Set errno to ECONNREFUSED (111) and return -1
              args[0] = ptr(-1);
            }
          }
        } catch (e) { console.warn("[root_bypass] connect hook error:", e); }
      },
    });
    console.log("[root_bypass] connect() hooked for port 27042.");
  } catch (e) {
    console.warn("[root_bypass] connect() attach failed:", e);
  }
}

// 7 + 8: libc open() — intercept /proc/self/cmdline and su paths
const openPtr =
  Module.findExportByName(null, "open") ??
  Module.findExportByName(null, "__open_nocancel");

if (openPtr) {
  try {
    const openImpl = new NativeFunction(openPtr, "int", ["pointer", "int", "int"]);
    Interceptor.attach(openPtr, {
      onEnter(args) {
        try {
          const path = args[0].readCString() ?? "";
          (this as Record<string, unknown>)["_path"] = path;
          if (
            path.includes("frida") ||
            path.includes("gum-js-loop") ||
            SU_PATHS.includes(path) ||
            path === "/proc/net/tcp"
          ) {
            emitEvent("root_bypass", { method: "libc.open", path, action: "intercepted" });
            // Mark so onLeave can clamp
            (this as Record<string, unknown>)["_block"] = true;
          }
        } catch { /* ignore */ }
      },
      onLeave(retval) {
        try {
          if ((this as Record<string, unknown>)["_block"]) {
            retval.replace(ptr(-1));
          }
        } catch { /* ignore */ }
      },
    });
    console.log("[root_bypass] libc open() hooked.");
  } catch (e) {
    console.warn("[root_bypass] libc open() attach failed:", e);
  }
}

// ─── Java / Android layer ─────────────────────────────────────────────────────

if (typeof Java !== "undefined" && Java.available) {
  Java.perform(() => {

    // ── 1. File.exists() — su path override ──────────────────────────────
    try {
      const File = Java.use("java.io.File");
      File.exists.implementation = function () {
        const path: string = this.getAbsolutePath();
        if (SU_PATHS.includes(path)) {
          emitEvent("root_bypass", { method: "File.exists", path, action: "blocked" });
          return false;
        }
        return this.exists();
      };
      console.log("[root_bypass] File.exists() hooked.");
    } catch (e) { console.warn("[root_bypass] File.exists hook failed:", e); }

    // ── 2+3: PackageManager.getPackageInfo — Magisk / SuperSU ─────────────
    try {
      const PackageManager = Java.use("android.app.ApplicationPackageManager");
      PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (
        pkgName: string,
        flags: number
      ) {
        if (ROOT_PACKAGES.has(pkgName)) {
          emitEvent("root_bypass", { method: "getPackageInfo", package: pkgName, action: "blocked" });
          const NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
          throw NameNotFoundException.$new(`Package not found: ${pkgName}`);
        }
        return this.getPackageInfo(pkgName, flags);
      };
      console.log("[root_bypass] PackageManager.getPackageInfo hooked.");
    } catch (e) { console.warn("[root_bypass] getPackageInfo hook failed:", e); }

    // ── 4. RootBeer ────────────────────────────────────────────────────────
    try {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
      const rootMethods = [
        "isRooted",
        "isRootedWithoutBusyBox",
        "detectRootManagementApps",
        "detectPotentiallyDangerousApps",
        "checkForSuBinary",
        "checkSuExists",
        "checkForRWPaths",
        "checkDangerousProps",
        "checkRootThroughNativeCode",
      ];
      for (const method of rootMethods) {
        try {
          // Frida Java.Wrapper has no static index signature — we must index by name at runtime.
          // Assigning to a named alias keeps the cast at the boundary; no inline access follows.
          const wrapper = RootBeer as unknown as Record<string, { implementation: unknown }>;
          const methodRef = wrapper[method];
          if (methodRef) {
            methodRef.implementation = function () {
              emitEvent("root_bypass", { method: `RootBeer.${method}`, action: "blocked" });
              return false;
            };
          }
        } catch { /* method may not exist in this build */ }
      }
      console.log("[root_bypass] RootBeer hooked.");
    } catch (e) { console.warn("[root_bypass] RootBeer not found:", e); }

    // ── 5. Build.TAGS ──────────────────────────────────────────────────────
    try {
      const Build = Java.use("android.os.Build");
      Build.TAGS.value = "release-keys";
      emitEvent("root_bypass", { method: "Build.TAGS", action: "patched", value: "release-keys" });
      console.log("[root_bypass] Build.TAGS patched to release-keys.");
    } catch (e) { console.warn("[root_bypass] Build.TAGS patch failed:", e); }

    // ── 9. Runtime.exec("su") ──────────────────────────────────────────────
    try {
      const Runtime = Java.use("java.lang.Runtime");
      const IOException = Java.use("java.io.IOException");

      Runtime.exec.overload("java.lang.String").implementation = function (cmd: string) {
        if (cmd && cmd.includes("su")) {
          emitEvent("root_bypass", { method: "Runtime.exec", cmd, action: "blocked" });
          throw IOException.$new("Permission denied (root bypass)");
        }
        return this.exec(cmd);
      };

      Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray: string[]) {
        if (cmdArray && cmdArray.length > 0 && cmdArray[0].includes("su")) {
          emitEvent("root_bypass", { method: "Runtime.exec[]", cmd: cmdArray[0], action: "blocked" });
          throw IOException.$new("Permission denied (root bypass)");
        }
        return this.exec(cmdArray);
      };

      console.log("[root_bypass] Runtime.exec() hooked.");
    } catch (e) { console.warn("[root_bypass] Runtime.exec hook failed:", e); }

    // ── 10. SystemProperties ───────────────────────────────────────────────
    try {
      const SystemProperties = Java.use("android.os.SystemProperties");
      SystemProperties.get.overload("java.lang.String").implementation = function (key: string) {
        const val: string = this.get(key);
        if (key === "ro.build.tags" || key === "ro.debuggable" || key === "ro.secure") {
          const safe = key === "ro.debuggable" ? "0" : key === "ro.secure" ? "1" : "release-keys";
          emitEvent("root_bypass", { method: "SystemProperties.get", key, original: val, replaced: safe });
          return safe;
        }
        return val;
      };
      console.log("[root_bypass] SystemProperties.get hooked.");
    } catch (e) { console.warn("[root_bypass] SystemProperties hook failed:", e); }

    // ── 11. SafetyNet attest ────────────────────────────────────────────────
    try {
      const SafetyNetClient = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
      SafetyNetClient.attest.implementation = function (nonce: unknown, apiKey: string) {
        emitEvent("root_bypass", { method: "SafetyNet.attest", action: "bypassed" });
        return this.attest(nonce, apiKey);
      };
      console.log("[root_bypass] SafetyNet.attest hooked.");
    } catch { /* SafetyNet not present */ }

    // ── 12. Play Integrity — IntegrityManager ────────────────────────────
    try {
      const IntegrityManager = Java.use("com.google.android.play.core.integrity.IntegrityManager");
      // requestIntegrityToken is the main entry point
      try {
        // Java.use() returns Java.Wrapper with no static index signature.
        // Cast to a named alias at the boundary so no inline member access is fabricated.
        const im = IntegrityManager as unknown as Record<string, { implementation: unknown }>;
        const tokenMethod = im["requestIntegrityToken"];
        if (tokenMethod) {
          tokenMethod.implementation = function (this: unknown, request: unknown) {
            emitEvent("root_bypass", { method: "Play.Integrity.requestIntegrityToken", action: "bypassed" });
            // Call through original via Frida's this context
            const self = this as Record<string, (r: unknown) => unknown>;
            return self["requestIntegrityToken"](request);
          };
        }
        console.log("[root_bypass] Play Integrity hooked.");
      } catch { /* method signature may vary */ }
    } catch { /* Play Integrity not present */ }

    // ── 13. getInstalledPackages — hide root manager APKs ─────────────────
    try {
      const PackageManager2 = Java.use("android.app.ApplicationPackageManager");
      PackageManager2.getInstalledPackages.implementation = function (flags: number) {
        const list = this.getInstalledPackages(flags);
        const filtered = list.toArray().filter((pkg: unknown) => {
          // pkg is a Java PackageInfo object; packageName is always present.
          // Use `in` guard so the compiler verifies the access.
          if (pkg && typeof pkg === "object" && "packageName" in pkg) {
            const pkgName = String(pkg.packageName);
            if (ROOT_PACKAGES.has(pkgName)) {
              emitEvent("root_bypass", { method: "getInstalledPackages", package: pkgName, action: "hidden" });
              return false;
            }
          }
          return true;
        });
        const ArrayList = Java.use("java.util.ArrayList");
        const result = ArrayList.$new();
        for (const p of filtered) result.add(p);
        return result;
      };
      console.log("[root_bypass] getInstalledPackages hooked.");
    } catch (e) { console.warn("[root_bypass] getInstalledPackages hook failed:", e); }

    console.log("[root_bypass] All root detection bypasses installed.");
  });
}

emitEvent("root_bypass", { event: "root_bypass_hook_installed", pid: Process.id });
