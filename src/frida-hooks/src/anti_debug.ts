/**
 * anti_debug.ts — Anti-debugging and Frida self-detection bypass
 *
 * Covers:
 *   macOS/iOS : ptrace(PT_DENY_ATTACH), sysctl kern.proc.pid flags
 *   Linux     : ptrace, /proc/self/status TracerPid replacement
 *   Windows   : IsDebuggerPresent stub
 *   Android   : Debug.isDebuggerConnected, ApplicationInfo.FLAG_DEBUGGABLE
 *   Universal : Frida-server port-scan detection bypass
 */

"use strict";

// ─── structured event emitter ─────────────────────────────────────────────────

function emitEvent(hook: string, data: Record<string, unknown>): void {
  send(
    JSON.stringify({
      type: "hook_event",
      hook,
      timestamp: new Date().toISOString(),
      ...data,
    })
  );
}

// ─── ptrace (macOS/iOS/Linux) ─────────────────────────────────────────────────

const ptracePtr = Module.findExportByName(null, "ptrace");
if (ptracePtr) {
  // ptrace(request, pid, addr, data) -> long
  // PT_DENY_ATTACH = 31 (macOS/iOS), PTRACE_TRACEME = 0 (Linux)
  Interceptor.attach(ptracePtr, {
    onEnter(args) {
      const req = args[0].toInt32();
      if (req === 31 /* PT_DENY_ATTACH */ || req === 0 /* PTRACE_TRACEME */) {
        emitEvent("anti_debug", {
          event: "ptrace_bypass",
          request: req,
          platform: req === 31 ? "macOS/iOS" : "Linux",
        });
        // Overwrite request with a harmless value (PTRACE_PEEKTEXT = 1 on Linux)
        args[0] = ptr(1);
      }
    },
    onLeave(retval) {
      // Force return 0 (success / no-deny) for any ptrace that might still fire deny logic
      if (retval.toInt32() < 0) {
        retval.replace(ptr(0));
      }
    },
  });
}

// ─── sysctl — suppress kern.proc.pid P_TRACED flag (macOS/iOS) ───────────────

const sysctlPtr = Module.findExportByName(null, "sysctl");
if (sysctlPtr) {
  // int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
  Interceptor.attach(sysctlPtr, {
    onEnter(args) {
      this.namePtr = args[0];
      this.oldp = args[2];
    },
    onLeave(retval) {
      if (retval.toInt32() !== 0) return;
      // name[0]=1 (CTL_KERN), name[1]=14 (KERN_PROC), name[2]=1 (KERN_PROC_PID)
      const namePtr = this.namePtr as NativePointer;
      if (namePtr.isNull()) return;
      const n0 = namePtr.readS32();
      const n1 = namePtr.add(4).readS32();
      const n2 = namePtr.add(8).readS32();
      if (n0 === 1 && n1 === 14 && n2 === 1) {
        const oldp = this.oldp as NativePointer;
        if (!oldp.isNull()) {
          // kinfo_proc.kp_proc.p_flag is at offset 32; P_TRACED = 0x800
          const flagOffset = 32;
          const flags = oldp.add(flagOffset).readU32();
          if (flags & 0x800) {
            oldp.add(flagOffset).writeU32(flags & ~0x800);
            emitEvent("anti_debug", {
              event: "sysctl_kern_proc_pid_traced_cleared",
              original_flags: flags,
            });
          }
        }
      }
    },
  });
}

// ─── IsDebuggerPresent (Windows stub) ────────────────────────────────────────

const isDebuggerPresentPtr = Module.findExportByName(
  "kernel32.dll",
  "IsDebuggerPresent"
);
if (isDebuggerPresentPtr) {
  Interceptor.replace(
    isDebuggerPresentPtr,
    new NativeCallback(
      () => {
        emitEvent("anti_debug", { event: "IsDebuggerPresent_stubbed" });
        return 0; // FALSE
      },
      "int",
      []
    )
  );
}

// ─── /proc/self/status TracerPid bypass (Linux) ──────────────────────────────

// Hook open/read to replace "TracerPid:\t<N>" with "TracerPid:\t0"
const openPtr =
  Module.findExportByName(null, "open") ??
  Module.findExportByName(null, "__open_nocancel");

if (openPtr) {
  const tracerPidRe = /TracerPid:\s*\d+/;
  const openFds = new Map<number, boolean>();

  Interceptor.attach(openPtr, {
    onEnter(args) {
      this.path = args[0].readCString();
    },
    onLeave(retval) {
      const fd = retval.toInt32();
      if (
        fd >= 0 &&
        typeof this.path === "string" &&
        this.path.includes("/proc/self/status")
      ) {
        openFds.set(fd, true);
        emitEvent("anti_debug", {
          event: "proc_self_status_open_intercepted",
          fd,
        });
      }
    },
  });

  const readPtr = Module.findExportByName(null, "read");
  if (readPtr) {
    Interceptor.attach(readPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.count = args[2].toUInt32();
      },
      onLeave(retval) {
        const n = retval.toInt32();
        if (n <= 0) return;
        const fd: number = this.fd;
        if (!openFds.has(fd)) return;
        const buf = this.buf as NativePointer;
        const bytes = buf.readByteArray(n);
        if (!bytes) return;
        const str = String.fromCharCode(...Array.from(new Uint8Array(bytes)));
        if (tracerPidRe.test(str)) {
          const patched = str.replace(tracerPidRe, "TracerPid:\t0");
          buf.writeUtf8String(patched);
          retval.replace(ptr(patched.length));
          emitEvent("anti_debug", {
            event: "TracerPid_zeroed",
            fd,
          });
        }
      },
    });
  }

  const closePtr = Module.findExportByName(null, "close");
  if (closePtr) {
    Interceptor.attach(closePtr, {
      onEnter(args) {
        openFds.delete(args[0].toInt32());
      },
    });
  }
}

// ─── Frida self-detection: port scan bypass ───────────────────────────────────
// Apps scan 27042 (frida-server default) via connect(); return ECONNREFUSED to hide it.

const connectPtr = Module.findExportByName(null, "connect");
if (connectPtr) {
  // connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) -> int
  const FRIDA_PORT = 27042;
  Interceptor.attach(connectPtr, {
    onEnter(args) {
      const addrPtr = args[1];
      if (addrPtr.isNull()) return;
      // sockaddr_in: family(2) + port(2 big-endian) + addr(4)
      const family = addrPtr.readU16();
      if (family === 2 /* AF_INET */) {
        const portBE = addrPtr.add(2).readU16();
        const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
        if (port === FRIDA_PORT) {
          this.blocking = true;
          emitEvent("anti_debug", {
            event: "frida_port_scan_blocked",
            port,
            note: "Frida-server detection attempt suppressed",
          });
        }
      }
    },
    onLeave(retval) {
      if (this.blocking) {
        // ECONNREFUSED = 111 Linux / 61 macOS — make it look like port is closed
        retval.replace(ptr(-1));
      }
    },
  });
}

// ─── Java/Android layer ───────────────────────────────────────────────────────

if (typeof Java !== "undefined" && Java.available) {
  Java.perform(() => {
    // android.os.Debug.isDebuggerConnected / waitingForDebugger
    try {
      const Debug = Java.use("android.os.Debug");
      Debug.isDebuggerConnected.implementation = function () {
        emitEvent("anti_debug", {
          event: "Debug.isDebuggerConnected_bypassed",
        });
        return false;
      };
      Debug.waitingForDebugger.implementation = function () {
        emitEvent("anti_debug", {
          event: "Debug.waitingForDebugger_bypassed",
        });
        return false;
      };
    } catch (e) {
      console.log("[anti_debug] Debug hook: " + String(e));
    }

    // ApplicationInfo.FLAG_DEBUGGABLE — clear bit 1
    try {
      const AppInfo = Java.use("android.content.pm.ApplicationInfo");
      const current = AppInfo.flags.value as number;
      AppInfo.flags.value = current & ~2;
      emitEvent("anti_debug", {
        event: "FLAG_DEBUGGABLE_cleared",
        was: current,
      });
    } catch (e) {
      console.log("[anti_debug] FLAG_DEBUGGABLE: " + String(e));
    }

    // Settings.Secure ANDROID_ID fingerprint
    try {
      const Secure = Java.use("android.provider.Settings$Secure");
      Secure.getString.overload(
        "android.content.ContentResolver",
        "java.lang.String"
      ).implementation = function (cr: unknown, name: unknown) {
        const result: unknown = this.getString(cr, name);
        if (name === "android_id") {
          emitEvent("anti_debug", {
            event: "ANDROID_ID_read",
            risk: "Device fingerprinting / anti-tamper check",
          });
        }
        return result;
      };
    } catch (e) {
      console.log("[anti_debug] ANDROID_ID hook: " + String(e));
    }

    // PackageManager signature check (tamper detection)
    try {
      const PM = Java.use("android.content.pm.PackageManager");
      PM.getPackageInfo.overload(
        "java.lang.String",
        "int"
      ).implementation = function (pkg: unknown, flags: unknown) {
        const result: unknown = this.getPackageInfo(pkg, flags);
        if (typeof flags === "number" && (flags & 64) !== 0) {
          emitEvent("anti_debug", {
            event: "signature_check_intercepted",
            package: String(pkg),
            risk: "APK signature verification (tamper detection)",
          });
        }
        return result;
      };
    } catch (e) {
      console.log("[anti_debug] PackageManager hook: " + String(e));
    }
  });
}

emitEvent("anti_debug", { event: "anti_debug_hook_installed", pid: Process.id });
