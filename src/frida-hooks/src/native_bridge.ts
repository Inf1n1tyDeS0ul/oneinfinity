/**
 * native_bridge.ts — dynamic library loading detector
 *
 * Hooks dlopen and dlsym to capture every native library loaded at runtime
 * and every symbol resolved dynamically.  Useful for detecting obfuscated
 * packing, reflective loading, and native-layer secret access.
 */

"use strict";

function emitEvent(hook: string, data: Record<string, unknown>): void {
    send(JSON.stringify({ type: "hook_event", hook, ts: Date.now() / 1000, ...data }));
}

// ── dlopen ────────────────────────────────────────────────────────────────────

const dlopenPtr = Module.findExportByName(null, "dlopen");
if (dlopenPtr) {
    Interceptor.attach(dlopenPtr, {
        onEnter(args) {
            const pathPtr = args[0];
            const flags   = args[1].toInt32();
            const libPath = pathPtr.isNull() ? "<main>" : (pathPtr.readCString() ?? "<null>");
            (this as { libPath: string }).libPath = libPath;
            emitEvent("dlopen", { path: libPath, flags });
        },
        onLeave(retval) {
            emitEvent("dlopen_result", {
                path:   (this as { libPath: string }).libPath,
                handle: retval.toString(),
                ok:     !retval.isNull(),
            });
        },
    });
}

// ── dlsym ─────────────────────────────────────────────────────────────────────

// Symbol names that indicate sensitive operations when resolved at runtime
const SENSITIVE_SYMBOLS = new Set([
    "SecItemCopyMatching",
    "SecKeychainItemCopyContent",
    "CCCrypt",
    "CC_MD5",
    "CC_SHA1",
    "SSL_CTX_set_verify",
    "X509_verify_cert",
    "pthread_create",
    "ptrace",
    "dlopen",
]);

const dlsymPtr = Module.findExportByName(null, "dlsym");
if (dlsymPtr) {
    Interceptor.attach(dlsymPtr, {
        onEnter(args) {
            const symPtr = args[1];
            const symbol = symPtr.isNull() ? "<null>" : (symPtr.readCString() ?? "<null>");
            (this as { symbol: string }).symbol = symbol;
            const sensitive = SENSITIVE_SYMBOLS.has(symbol);
            if (sensitive) {
                emitEvent("dlsym_sensitive", { symbol, sensitive: true });
            }
        },
        onLeave(retval) {
            emitEvent("dlsym_result", {
                symbol:  (this as { symbol: string }).symbol,
                address: retval.toString(),
                ok:      !retval.isNull(),
            });
        },
    });
}

// ── Android linker: android_dlopen_ext ───────────────────────────────────────

const androidDlopenPtr = Module.findExportByName(null, "android_dlopen_ext");
if (androidDlopenPtr) {
    Interceptor.attach(androidDlopenPtr, {
        onEnter(args) {
            const libPath = args[0].isNull() ? "<null>" : (args[0].readCString() ?? "<null>");
            emitEvent("android_dlopen_ext", { path: libPath });
        },
    });
}

// ── module-load observer ──────────────────────────────────────────────────────

Process.setExceptionHandler((_details) => false);  // don't swallow exceptions

// Observe every new module that gets mapped into the process
try {
    // Frida >= 16: Module.load hook via Process event
    (Process as unknown as {
        on(event: "module-loaded", cb: (mod: Module) => void): void;
    }).on("module-loaded", (mod: Module) => {
        emitEvent("module_loaded", {
            name: mod.name,
            base: mod.base.toString(),
            size: mod.size,
            path: mod.path,
        });
    });
} catch {
    // Older Frida builds — module-loaded event not available, silent fail
}

emitEvent("native_bridge_ready", { pid: Process.id });
