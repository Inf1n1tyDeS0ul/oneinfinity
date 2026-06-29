/**
 * ssl_hook.ts — SSL/TLS interception and certificate pinning bypass
 *
 * Covers:
 *   macOS/iOS : Security.framework  (SSLRead, SSLWrite, SecTrustEvaluate, SecTrustEvaluateWithError,
 *                                    SecItemCopyMatching, SSLHandshake)
 *   Android   : libssl.so           (SSL_read, SSL_write, SSL_CTX_set_verify)
 *   Linux     : libssl.so.3         (same exports)
 *   Java layer: TrustManager, OkHttp3 CertificatePinner, Conscrypt, HttpsURLConnection
 */

"use strict";

// ─── helpers ────────────────────────────────────────────────────────────────

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

function bufToHexAscii(
  ptr: NativePointer,
  len: number
): { hex: string; ascii: string } {
  const MAX = 512;
  const n = Math.min(len, MAX);
  const bytes = ptr.readByteArray(n);
  if (!bytes) return { hex: "", ascii: "" };
  const arr = Array.from(new Uint8Array(bytes));
  const hex = arr.map((b) => b.toString(16).padStart(2, "0")).join("");
  const ascii = arr
    .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
    .join("");
  return { hex: hex + (len > MAX ? "…" : ""), ascii };
}

// ─── native SSL_read / SSL_write (Android libssl.so, Linux libssl.so.3) ──────

function hookNativeSsl(libName: string): void {
  const sslRead = Module.findExportByName(libName, "SSL_read");
  const sslWrite = Module.findExportByName(libName, "SSL_write");
  const sslCtxSetVerify = Module.findExportByName(
    libName,
    "SSL_CTX_set_verify"
  );

  if (sslRead) {
    // SSL_read(SSL *ssl, void *buf, int num) -> int
    Interceptor.attach(sslRead, {
      onEnter(args) {
        this.buf = args[1];
        this.num = args[2].toInt32();
      },
      onLeave(retval) {
        const n = retval.toInt32();
        if (n <= 0) return;
        const { hex, ascii } = bufToHexAscii(this.buf as NativePointer, n);
        emitEvent("ssl", {
          direction: "read",
          lib: libName,
          length: n,
          hex,
          ascii,
        });
      },
    });
  }

  if (sslWrite) {
    // SSL_write(SSL *ssl, const void *buf, int num) -> int
    Interceptor.attach(sslWrite, {
      onEnter(args) {
        const n = args[2].toInt32();
        const { hex, ascii } = bufToHexAscii(args[1], n);
        emitEvent("ssl", {
          direction: "write",
          lib: libName,
          length: n,
          hex,
          ascii,
        });
      },
    });
  }

  // Certificate pinning bypass: SSL_CTX_set_verify — replace callback with null (no-verify)
  if (sslCtxSetVerify) {
    Interceptor.attach(sslCtxSetVerify, {
      onEnter(args) {
        // args[1] = mode, args[2] = verify_callback
        // Force SSL_VERIFY_NONE (0) and null callback
        args[1] = ptr(0);
        args[2] = ptr(0);
        emitEvent("ssl", {
          event: "SSL_CTX_set_verify_bypassed",
          lib: libName,
          note: "Certificate verification disabled",
        });
      },
    });
  }
}

// ─── macOS/iOS Security.framework ────────────────────────────────────────────

function hookSecurityFramework(): void {
  const secLib = "Security";

  // SSLRead(SSLContextRef ctx, void *data, size_t dataLength, size_t *processed)
  const sslReadPtr = Module.findExportByName(secLib, "SSLRead");
  if (sslReadPtr) {
    Interceptor.attach(sslReadPtr, {
      onEnter(args) {
        this.dataBuf = args[1];
        this.processedPtr = args[3];
      },
      onLeave(retval) {
        if (retval.toInt32() !== 0) return; // errSecSuccess = 0
        const processedPtr = this.processedPtr as NativePointer;
        const processed = processedPtr.readUInt();
        if (processed === 0) return;
        const { hex, ascii } = bufToHexAscii(
          this.dataBuf as NativePointer,
          processed
        );
        emitEvent("ssl", {
          direction: "read",
          lib: secLib,
          fn: "SSLRead",
          length: processed,
          hex,
          ascii,
        });
      },
    });
  }

  // SSLWrite(SSLContextRef ctx, const void *data, size_t dataLength, size_t *processed)
  const sslWritePtr = Module.findExportByName(secLib, "SSLWrite");
  if (sslWritePtr) {
    Interceptor.attach(sslWritePtr, {
      onEnter(args) {
        const len = args[2].toUInt32();
        const { hex, ascii } = bufToHexAscii(args[1], len);
        emitEvent("ssl", {
          direction: "write",
          lib: secLib,
          fn: "SSLWrite",
          length: len,
          hex,
          ascii,
        });
      },
    });
  }

  // SecTrustEvaluate — return errSecSuccess (0) → trusted
  const secTrustEval = Module.findExportByName(secLib, "SecTrustEvaluate");
  if (secTrustEval) {
    Interceptor.attach(secTrustEval, {
      onLeave(retval) {
        emitEvent("ssl", {
          event: "SecTrustEvaluate_bypassed",
          original_result: retval.toInt32(),
        });
        retval.replace(ptr(0)); // errSecSuccess
      },
    });
  }

  // SecTrustEvaluateWithError (iOS 12+) — return true
  const secTrustEvalWithErr = Module.findExportByName(
    secLib,
    "SecTrustEvaluateWithError"
  );
  if (secTrustEvalWithErr) {
    Interceptor.attach(secTrustEvalWithErr, {
      onLeave(retval) {
        emitEvent("ssl", { event: "SecTrustEvaluateWithError_bypassed" });
        retval.replace(ptr(1)); // true = trusted
      },
    });
  }

  // SecItemCopyMatching — log keychain queries (certificates, keys)
  const secItemCopy = Module.findExportByName(secLib, "SecItemCopyMatching");
  if (secItemCopy) {
    Interceptor.attach(secItemCopy, {
      onLeave(retval) {
        emitEvent("ssl", {
          event: "SecItemCopyMatching",
          status: retval.toInt32(),
          note: "Keychain item lookup observed",
        });
      },
    });
  }

  // SSLHandshake — log TLS negotiation
  const sslHandshake = Module.findExportByName(secLib, "SSLHandshake");
  if (sslHandshake) {
    Interceptor.attach(sslHandshake, {
      onEnter(_args) {
        emitEvent("ssl", { event: "SSLHandshake_enter", lib: secLib });
      },
      onLeave(retval) {
        emitEvent("ssl", {
          event: "SSLHandshake_leave",
          result: retval.toInt32(),
        });
      },
    });
  }
}

// ─── Java/Android layer ───────────────────────────────────────────────────────

function hookJavaLayer(): void {
  if (typeof Java === "undefined" || !Java.available) return;

  Java.perform(() => {
    // 1. Permissive TrustManager
    try {
      const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
      const SSLContext = Java.use("javax.net.ssl.SSLContext");
      const TrustAll = Java.registerClass({
        name: "com.oneinfinity.bypass.TrustAllManager",
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted(_chain: unknown, _authType: unknown) {},
          checkServerTrusted(_chain: unknown, authType: unknown) {
            emitEvent("ssl", {
              event: "checkServerTrusted_bypassed",
              authType: String(authType),
            });
          },
          getAcceptedIssuers() {
            return [];
          },
        },
      });
      const ctx = SSLContext.getInstance("TLS");
      ctx.init(null, [TrustAll.$new()], null);
      SSLContext.getDefault.implementation = function () {
        emitEvent("ssl", { event: "SSLContext.getDefault_patched" });
        return ctx;
      };
    } catch (e) {
      console.log("[ssl_hook] TrustManager bypass: " + String(e));
    }

    // 2. OkHttp3 CertificatePinner
    try {
      const CP = Java.use("okhttp3.CertificatePinner");
      CP.check
        .overload("java.lang.String", "java.util.List")
        .implementation = function (hostname: unknown, _peerCerts: unknown) {
        emitEvent("ssl", {
          event: "OkHttp3.CertificatePinner.check_bypassed",
          hostname: String(hostname),
        });
      };
      CP.check
        .overload(
          "java.lang.String",
          "[Ljava.security.cert.Certificate;"
        )
        .implementation = function (hostname: unknown, _certs: unknown) {
        emitEvent("ssl", {
          event: "OkHttp3.CertificatePinner.check_legacy_bypassed",
          hostname: String(hostname),
        });
      };
    } catch (e) {
      console.log("[ssl_hook] OkHttp3 CertificatePinner: " + String(e));
    }

    // 3. Conscrypt TrustManagerImpl
    try {
      const TMI = Java.use(
        "com.android.org.conscrypt.TrustManagerImpl"
      );
      TMI.verifyChain.implementation = function (
        untrustedChain: unknown,
        _trustAnchorChain: unknown,
        host: unknown,
        _clientAuth: unknown,
        _ocspData: unknown,
        _tlsSctData: unknown
      ) {
        emitEvent("ssl", {
          event: "Conscrypt.verifyChain_bypassed",
          host: String(host),
        });
        return untrustedChain;
      };
    } catch (e) {
      console.log("[ssl_hook] Conscrypt: " + String(e));
    }

    // 4. HttpsURLConnection HostnameVerifier
    try {
      const HTTPS = Java.use("javax.net.ssl.HttpsURLConnection");
      const AllowAll = Java.registerClass({
        name: "com.oneinfinity.bypass.AllHostnameVerifier",
        implements: [Java.use("javax.net.ssl.HostnameVerifier")],
        methods: {
          verify(_hostname: unknown, _session: unknown): boolean {
            return true;
          },
        },
      });
      HTTPS.setDefaultHostnameVerifier.implementation = function (
        _verifier: unknown
      ) {
        emitEvent("ssl", {
          event: "HttpsURLConnection.HostnameVerifier_replaced",
        });
        this.setDefaultHostnameVerifier(AllowAll.$new());
      };
    } catch (e) {
      console.log("[ssl_hook] HostnameVerifier: " + String(e));
    }

    // 5. Flutter libflutter.so native SSL verify
    try {
      const flutterVerify = Module.findExportByName(
        "libflutter.so",
        "ssl_crypto_x509_session_verify_cert_chain"
      );
      if (flutterVerify) {
        Interceptor.attach(flutterVerify, {
          onLeave(retval) {
            emitEvent("ssl", { event: "Flutter_ssl_verify_bypassed" });
            retval.replace(ptr(1));
          },
        });
      }
    } catch (e) {
      console.log("[ssl_hook] Flutter SSL: " + String(e));
    }
  });
}

// ─── entry point ─────────────────────────────────────────────────────────────

// Android
hookNativeSsl("libssl.so");
// Linux
hookNativeSsl("libssl.so.3");
// macOS / iOS
hookSecurityFramework();
// Java/Android JVM layer
hookJavaLayer();

emitEvent("ssl", { event: "ssl_hook_installed", pid: Process.id });
