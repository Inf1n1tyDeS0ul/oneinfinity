/**
 * process_injection.ts — Process injection and execution monitoring
 *
 * Hooks:
 *   All platforms : dlopen, dlsym, mprotect (PROT_EXEC detection)
 *   macOS/iOS     : NSTask launch
 *   Linux/Android : execv, execve, execvp
 *
 * Emits NDJSON process_event records via send().
 */

"use strict";

// ─── helpers ─────────────────────────────────────────────────────────────────

function emitEvent(data: Record<string, unknown>): void {
  send(
    JSON.stringify({
      type: "process_event",
      pid: Process.id,
      timestamp: Date.now(),
      ...data,
    })
  );
}

function ptrToStr(ptr: NativePointer): string {
  try {
    return ptr.readUtf8String() ?? "";
  } catch {
    return ptr.toString();
  }
}

// ─── module map snapshot ──────────────────────────────────────────────────────

try {
  emitEvent({
    subtype: "module_map",
    modules: Process.enumerateModules().map((m) => ({
      name: m.name,
      base: m.base.toString(),
      size: m.size,
      path: m.path,
    })),
  });
} catch {
  // enumerateModules failed — non-fatal
}

// ─── dlopen ──────────────────────────────────────────────────────────────────

try {
  const dlopenPtr = Module.findExportByName(null, "dlopen");
  if (dlopenPtr) {
    Interceptor.attach(dlopenPtr, {
      onEnter(args) {
        this.path = ptrToStr(args[0]);
        this.flags = args[1].toInt32();
      },
      onLeave(retval) {
        emitEvent({
          subtype: "dlopen",
          path: this.path,
          flags: this.flags,
          handle: retval.toString(),
        });
      },
    });
  }
} catch {
  // dlopen not available — skip
}

// ─── dlsym ───────────────────────────────────────────────────────────────────

try {
  const dlsymPtr = Module.findExportByName(null, "dlsym");
  if (dlsymPtr) {
    Interceptor.attach(dlsymPtr, {
      onEnter(args) {
        this.handle = args[0].toString();
        this.symbol = ptrToStr(args[1]);
      },
      onLeave(retval) {
        emitEvent({
          subtype: "dlsym",
          handle: this.handle,
          symbol: this.symbol,
          resolved: retval.toString(),
        });
      },
    });
  }
} catch {
  // dlsym not available — skip
}

// ─── mprotect (PROT_EXEC detection) ──────────────────────────────────────────

const PROT_EXEC = 4;

try {
  const mprotectPtr = Module.findExportByName(null, "mprotect");
  if (mprotectPtr) {
    Interceptor.attach(mprotectPtr, {
      onEnter(args) {
        const prot = args[2].toInt32();
        if (prot & PROT_EXEC) {
          emitEvent({
            subtype: "mprotect_rwx",
            address: args[0].toString(),
            size: args[1].toUInt32(),
            prot,
          });
        }
      },
    });
  }
} catch {
  // mprotect not available — skip
}

// ─── macOS/iOS: NSTask launch ─────────────────────────────────────────────────

if (Process.platform === "darwin") {
  try {
    if (ObjC.available) {
      const NSTask = ObjC.classes.NSTask;
      if (NSTask) {
        const launchSel = NSTask["- launch"];
        if (launchSel) {
          Interceptor.attach(launchSel.implementation, {
            onEnter(args) {
              try {
                const task = new ObjC.Object(args[0]);
                const launchPath = task.launchPath
                  ? task.launchPath().toString()
                  : "<unknown>";
                let argv: string[] = [];
                try {
                  const argsObj = task.arguments();
                  if (argsObj) {
                    const count = argsObj.count().valueOf() as number;
                    for (let i = 0; i < count; i++) {
                      argv.push(argsObj.objectAtIndex_(i).toString());
                    }
                  }
                } catch {
                  // arguments unavailable
                }
                emitEvent({
                  subtype: "nstask_launch",
                  cmd: launchPath,
                  argv,
                });
              } catch {
                emitEvent({ subtype: "nstask_launch", cmd: "<parse_error>" });
              }
            },
          });
        }
      }
    }
  } catch {
    // NSTask not available — skip
  }
}

// ─── Linux/Android: exec family ──────────────────────────────────────────────

if (Process.platform === "linux") {
  const libcCandidates = ["libc.so", "libc.so.6", "libc.musl-x86_64.so.1"];

  function hookExec(lib: string, sym: string): void {
    try {
      const ptr = Module.findExportByName(lib, sym);
      if (!ptr) return;
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            const path = ptrToStr(args[0]);
            emitEvent({ subtype: "exec", syscall: sym, path });
          } catch {
            emitEvent({ subtype: "exec", syscall: sym, path: "<parse_error>" });
          }
        },
      });
    } catch {
      // symbol not found — skip
    }
  }

  for (const lib of libcCandidates) {
    hookExec(lib, "execv");
    hookExec(lib, "execve");
    hookExec(lib, "execvp");
    hookExec(lib, "execvpe");
  }
}
