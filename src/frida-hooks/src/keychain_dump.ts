/**
 * keychain_dump.ts — iOS Keychain extraction hook
 *
 * Hooks SecItemCopyMatching (and SecItemAdd/SecItemUpdate) to intercept
 * all keychain reads.  On success the result CFDictionary/CFData is decoded
 * and emitted via send().
 *
 * macOS/iOS only — guarded by ObjC.available check.
 */

"use strict";

function emitEvent(hook: string, data: Record<string, unknown>): void {
    send(JSON.stringify({ type: "hook_event", hook, ts: Date.now() / 1000, ...data }));
}

// ── CoreFoundation helpers ────────────────────────────────────────────────────

const CF = {
    StringGetCStringPtr: new NativeFunction(
        Module.findExportByName("CoreFoundation", "CFStringGetCStringPtr")!,
        "pointer", ["pointer", "uint32"]
    ),
    DataGetBytePtr: new NativeFunction(
        Module.findExportByName("CoreFoundation", "CFDataGetBytePtr")!,
        "pointer", ["pointer"]
    ),
    DataGetLength: new NativeFunction(
        Module.findExportByName("CoreFoundation", "CFDataGetLength")!,
        "long", ["pointer"]
    ),
    GetTypeID: new NativeFunction(
        Module.findExportByName("CoreFoundation", "CFGetTypeID")!,
        "ulong", ["pointer"]
    ),
    StringGetTypeID: new NativeFunction(
        Module.findExportByName("CoreFoundation", "CFStringGetTypeID")!,
        "ulong", []
    ),
    DataGetTypeID: new NativeFunction(
        Module.findExportByName("CoreFoundation", "CFDataGetTypeID")!,
        "ulong", []
    ),
};

const kCFStringEncodingUTF8 = 0x08000100;

function cfPtrToString(cfPtr: NativePointer): string | null {
    if (cfPtr.isNull()) return null;
    try {
        const cstr = CF.StringGetCStringPtr(cfPtr, kCFStringEncodingUTF8) as NativePointer;
        if (!cstr.isNull()) return cstr.readCString();
    } catch {
        // fall through
    }
    return null;
}

function cfDataToHex(cfPtr: NativePointer): string | null {
    if (cfPtr.isNull()) return null;
    try {
        const bp  = CF.DataGetBytePtr(cfPtr) as NativePointer;
        const len = CF.DataGetLength(cfPtr) as number;
        if (bp.isNull() || len <= 0) return null;
        const buf = bp.readByteArray(Math.min(len, 256));
        if (!buf) return null;
        return Array.from(new Uint8Array(buf))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
    } catch {
        return null;
    }
}

// ── ObjC layer — only on iOS/macOS ───────────────────────────────────────────

if (typeof ObjC !== "undefined" && ObjC.available) {

    // SecItemCopyMatching
    const secCopyPtr = Module.findExportByName("Security", "SecItemCopyMatching");
    if (secCopyPtr) {
        Interceptor.attach(secCopyPtr, {
            onEnter(args) {
                // args[0] = CFDictionaryRef query, args[1] = CFTypeRef* result
                (this as { resultPtrPtr: NativePointer }).resultPtrPtr = args[1];
            },
            onLeave(retval) {
                const status = retval.toInt32();
                if (status !== 0) return; // errSecSuccess = 0

                const resultPtrPtr = (this as { resultPtrPtr: NativePointer }).resultPtrPtr;
                if (resultPtrPtr.isNull()) return;

                try {
                    const resultPtr = resultPtrPtr.readPointer();
                    if (resultPtr.isNull()) return;

                    // Try to decode as string or data
                    const stringTypeID = CF.StringGetTypeID() as unknown as bigint | number;
                    const dataTypeID   = CF.DataGetTypeID()   as unknown as bigint | number;
                    const typeID       = CF.GetTypeID(resultPtr) as unknown as bigint | number;

                    let decoded: string | null = null;
                    if (typeID === stringTypeID) {
                        decoded = cfPtrToString(resultPtr);
                    } else if (typeID === dataTypeID) {
                        decoded = cfDataToHex(resultPtr);
                    }

                    emitEvent("keychain_read", {
                        status,
                        decoded: decoded ?? "<non-string/data result>",
                        severity: "critical",
                    });
                } catch {
                    // result pointer invalid — skip
                }
            },
        });
    }

    // SecItemAdd — capture secrets being stored
    const secAddPtr = Module.findExportByName("Security", "SecItemAdd");
    if (secAddPtr) {
        Interceptor.attach(secAddPtr, {
            onEnter(args) {
                emitEvent("keychain_add", {
                    query_ptr: args[0].toString(),
                    note: "SecItemAdd called — new keychain item being stored",
                });
            },
        });
    }

    emitEvent("keychain_dump_ready", { pid: Process.id, platform: "ios_macos" });

} else {
    emitEvent("keychain_dump_skipped", { reason: "ObjC runtime not available" });
}
