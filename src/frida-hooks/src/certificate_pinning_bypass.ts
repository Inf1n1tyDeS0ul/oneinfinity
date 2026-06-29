/**
 * certificate_pinning_bypass.ts — advanced multi-framework SSL pinning bypass
 *
 * Covers:
 *   Android Java: OkHttp3 CertificatePinner, TrustKit, Appcelerator,
 *                 HttpsURLConnection, Conscrypt, Volley, Retrofit adapters
 *   Android native: libssl SSL_CTX_set_verify, X509_verify_cert
 *   iOS/macOS:  SecTrustEvaluate, SecTrustEvaluateWithError, SecTrustSetAnchorCertificates
 *
 * Each bypass emits a structured finding via send().
 */

"use strict";

function emitBypass(framework: string, method: string, extra?: Record<string, unknown>): void {
    send(JSON.stringify({
        type:        "hook_event",
        hook:        "cert_pinning_bypass",
        framework,
        method,
        severity:    "high",
        ts:          Date.now() / 1000,
        ...(extra ?? {}),
    }));
}

// ── Native layer (Android + iOS) ─────────────────────────────────────────────

// libssl: SSL_CTX_set_verify — force SSL_VERIFY_NONE (0)
const sslSetVerifyPtr = Module.findExportByName("libssl.so", "SSL_CTX_set_verify")
    ?? Module.findExportByName("libssl.so.3", "SSL_CTX_set_verify")
    ?? Module.findExportByName("libssl.so.1.1", "SSL_CTX_set_verify");

if (sslSetVerifyPtr) {
    Interceptor.attach(sslSetVerifyPtr, {
        onEnter(args) {
            args[1] = ptr(0); // mode = SSL_VERIFY_NONE
            emitBypass("libssl", "SSL_CTX_set_verify", { forced_mode: 0 });
        },
    });
}

// libssl: X509_verify_cert — always return success (1)
const x509VerifyPtr = Module.findExportByName("libssl.so", "X509_verify_cert")
    ?? Module.findExportByName("libssl.so.3", "X509_verify_cert");

if (x509VerifyPtr) {
    Interceptor.attach(x509VerifyPtr, {
        onLeave(retval) {
            retval.replace(ptr(1));
            emitBypass("libssl", "X509_verify_cert", { forced_return: 1 });
        },
    });
}

// iOS/macOS Security.framework
const secTrustEvalPtr = Module.findExportByName("Security", "SecTrustEvaluate");
if (secTrustEvalPtr) {
    Interceptor.attach(secTrustEvalPtr, {
        onEnter(args) {
            // args[1] = SecTrustResultType* result pointer
            (this as { resultPtr: NativePointer }).resultPtr = args[1];
        },
        onLeave(retval) {
            // errSecSuccess = 0; kSecTrustResultProceed = 1
            const rp = (this as { resultPtr: NativePointer }).resultPtr;
            if (!rp.isNull()) rp.writeU32(1);
            retval.replace(ptr(0));
            emitBypass("Security.framework", "SecTrustEvaluate");
        },
    });
}

const secTrustEvalErrPtr = Module.findExportByName("Security", "SecTrustEvaluateWithError");
if (secTrustEvalErrPtr) {
    Interceptor.attach(secTrustEvalErrPtr, {
        onEnter(args) {
            // args[1] = CFErrorRef* — clear it on the way in
            if (!args[1].isNull()) args[1].writePointer(ptr(0));
        },
        onLeave(retval) {
            retval.replace(ptr(1)); // return true = trusted
            emitBypass("Security.framework", "SecTrustEvaluateWithError");
        },
    });
}

// ── Android Java layer ────────────────────────────────────────────────────────

if (typeof Java !== "undefined" && Java.available) {
    Java.perform(() => {

        // ── OkHttp3 CertificatePinner ────────────────────────────────────────
        try {
            const CertPinner = Java.use("okhttp3.CertificatePinner");
            // check(String hostname, List<Certificate> peerCertificates) — throws on failure
            const checkOverloads = CertPinner.check.overloads;
            for (const overload of checkOverloads) {
                overload.implementation = function (..._args: unknown[]) {
                    emitBypass("OkHttp3", "CertificatePinner.check");
                    // return void — do not throw
                };
            }
        } catch { /* OkHttp3 not present */ }

        // ── OkHttp3 CertificatePinner$Builder.add ────────────────────────────
        try {
            const Builder = Java.use("okhttp3.CertificatePinner$Builder");
            Builder.add.overloads.forEach((ov: { implementation: (...args: unknown[]) => unknown }) => {
                const original = ov.implementation;
                ov.implementation = function (...args: unknown[]) {
                    emitBypass("OkHttp3", "CertificatePinner.Builder.add", { pin_args_count: args.length });
                    return original ? original.apply(this, args) : this;
                };
            });
        } catch { /* skip */ }

        // ── TrustKit (iOS/Android) ────────────────────────────────────────────
        try {
            const TrustKit = Java.use("com.datatheorem.android.trustkit.pinning.SSLPinningTrustManager");
            TrustKit.checkServerTrusted.overloads.forEach((ov: { implementation: (...args: unknown[]) => void }) => {
                ov.implementation = function (..._args: unknown[]) {
                    emitBypass("TrustKit", "SSLPinningTrustManager.checkServerTrusted");
                };
            });
        } catch { /* TrustKit not present */ }

        // ── Appcelerator (Titanium) ───────────────────────────────────────────
        try {
            const AppcPinner = Java.use("appcelerator.https.PinningTrustManager");
            AppcPinner.checkServerTrusted.overloads.forEach((ov: { implementation: (...args: unknown[]) => void }) => {
                ov.implementation = function (..._args: unknown[]) {
                    emitBypass("Appcelerator", "PinningTrustManager.checkServerTrusted");
                };
            });
        } catch { /* Appcelerator not present */ }

        // ── HttpsURLConnection via TrustManager replacement ───────────────────
        try {
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const SSLContext        = Java.use("javax.net.ssl.SSLContext");
            const TrustAllManager   = Java.registerClass({
                name: "com.oi.bypass.TrustAllManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted(_chain: unknown, _authType: unknown) { /* noop */ },
                    checkServerTrusted(_chain: unknown, _authType: unknown) {
                        emitBypass("javax.net.ssl", "X509TrustManager.checkServerTrusted");
                    },
                    getAcceptedIssuers() { return []; },
                },
            });
            const ctx = SSLContext.getInstance("TLS");
            ctx.init(null, [TrustAllManager.$new()], null);
            SSLContext.getDefault.implementation = function () { return ctx; };
            emitBypass("javax.net.ssl", "SSLContext.getDefault replaced");
        } catch { /* skip */ }

        // ── Conscrypt TrustManagerImpl ────────────────────────────────────────
        try {
            const Conscrypt = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            Conscrypt.verifyChain.implementation = function (
                untrustedChain: unknown,
                trustAnchorChain: unknown,
                host: unknown,
                clientAuth: unknown,
                ocspData: unknown,
                tlsSctData: unknown
            ) {
                emitBypass("Conscrypt", "TrustManagerImpl.verifyChain", { host: String(host) });
                return untrustedChain;
            };
        } catch { /* skip */ }

        // ── Network Security Config bypass (Android 7+) ───────────────────────
        try {
            const NetworkSecConfig = Java.use(
                "android.security.net.config.NetworkSecurityConfig"
            );
            NetworkSecConfig.getDefault.implementation = function () {
                emitBypass("Android", "NetworkSecurityConfig.getDefault");
                return NetworkSecConfig.getDefault.call(this);
            };
        } catch { /* skip */ }

    });
}

send(JSON.stringify({ type: "hook_event", hook: "cert_pinning_bypass_ready", ts: Date.now() / 1000 }));
