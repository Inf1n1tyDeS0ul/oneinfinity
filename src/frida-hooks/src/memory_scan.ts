/**
 * memory_scan.ts — heap memory scanner for secrets
 *
 * Instruments malloc/free to track live allocations, then scans heap
 * regions for patterns matching API keys, JWTs, and bearer tokens.
 * Results are emitted via send() for the Python host to consume.
 */

"use strict";

// ── helpers ──────────────────────────────────────────────────────────────────

function emitEvent(hook: string, data: Record<string, unknown>): void {
    send(JSON.stringify({ type: "hook_event", hook, ts: Date.now() / 1000, ...data }));
}

// ── secret patterns ──────────────────────────────────────────────────────────

interface SecretPattern {
    name: string;
    pattern: RegExp;
    severity: string;
}

const SECRET_PATTERNS: readonly SecretPattern[] = [
    { name: "jwt",          pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: "critical" },
    { name: "bearer_token", pattern: /Bearer\s+[A-Za-z0-9\-._~+/]{20,}/i,                               severity: "high"     },
    { name: "aws_key",      pattern: /AKIA[0-9A-Z]{16}/,                                                 severity: "critical" },
    { name: "aws_secret",   pattern: /(?<![A-Za-z0-9])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/,             severity: "critical" },
    { name: "google_api",   pattern: /AIza[0-9A-Za-z\-_]{35}/,                                           severity: "high"     },
    { name: "private_key",  pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,                           severity: "critical" },
    { name: "password_kv",  pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']?[^\s"']{6,}/i,              severity: "high"     },
    { name: "api_key_kv",   pattern: /(?:api_key|apikey|api-key)\s*[=:]\s*["']?[A-Za-z0-9_\-]{16,}/i,  severity: "high"     },
];

// ── allocation tracker ───────────────────────────────────────────────────────

// Track live allocations: ptr (hex string) → size
const liveAllocs = new Map<string, number>();
const MAX_SCAN_SIZE = 4096; // bytes per allocation to scan
const MAX_TRACKED   = 50_000;

function scanBuffer(buf: ArrayBuffer, source: string): void {
    const view = new Uint8Array(buf);
    let text = "";
    for (let i = 0; i < view.length; i++) {
        const b = view[i];
        // Printable ASCII only
        text += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : " ";
    }
    for (const sp of SECRET_PATTERNS) {
        const m = sp.pattern.exec(text);
        if (m) {
            emitEvent("memory_secret", {
                pattern:  sp.name,
                severity: sp.severity,
                source,
                excerpt:  m[0].substring(0, 60),
            });
        }
    }
}

// ── malloc/free hooks ─────────────────────────────────────────────────────────

const mallocPtr = Module.findExportByName(null, "malloc");
const freePtr   = Module.findExportByName(null, "free");

if (mallocPtr) {
    Interceptor.attach(mallocPtr, {
        onEnter(args) {
            // Store requested size keyed by thread id for onLeave correlation
            (this as { reqSize: number }).reqSize = args[0].toInt32();
        },
        onLeave(retval) {
            if (retval.isNull()) return;
            const size: number = (this as { reqSize: number }).reqSize;
            if (size <= 0 || size > MAX_SCAN_SIZE) return;
            if (liveAllocs.size >= MAX_TRACKED) return;
            liveAllocs.set(retval.toString(), size);
        },
    });
}

if (freePtr) {
    Interceptor.attach(freePtr, {
        onEnter(args) {
            const key = args[0].toString();
            const size = liveAllocs.get(key);
            if (size === undefined) return;
            liveAllocs.delete(key);
            // Scan on free — the allocation is still valid until free returns
            try {
                const buf = args[0].readByteArray(size);
                if (buf) scanBuffer(buf, `heap@${key}`);
            } catch {
                // pointer no longer readable — skip
            }
        },
    });
}

// ── on-demand heap walk ───────────────────────────────────────────────────────

// Expose a RPC handler so the host can trigger a heap scan at any time
rpc.exports = {
    scanHeap(): number {
        let hits = 0;
        for (const [ptr, size] of liveAllocs) {
            try {
                const buf = ptr2native(ptr).readByteArray(Math.min(size, MAX_SCAN_SIZE));
                if (buf) { scanBuffer(buf, `rpc_heap@${ptr}`); hits++; }
            } catch {
                // skip unreadable
            }
        }
        return hits;
    },
    trackedCount(): number {
        return liveAllocs.size;
    },
};

function ptr2native(hex: string): NativePointer {
    return ptr(hex);
}
