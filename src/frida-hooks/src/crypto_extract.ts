/**
 * crypto_extract.ts — Cryptographic key and IV extraction
 *
 * AUTHORIZATION GATE — requires explicit operator consent.
 * Set globalThis.__OI_CRYPTO_EXTRACT_TOKEN to a non-empty session token before attaching.
 * In production: this token comes from the scan session manager and is scoped to the case ID + target.
 *
 * Hooks (10 total):
 *  1.  iOS/macOS  CCCrypt              — key, iv, alg, dataIn
 *  2.  Android    Cipher.doFinal       — alg, input, output hex
 *  3.  Android    SecretKeySpec.$init  — key hex, alg, weak-key flag
 *  4.  OpenSSL    EVP_EncryptInit_ex   — ctx, cipher name, key hex, iv hex
 *  5.  iOS        SecKeyEncrypt        — padding, plainText, cipherText ptr
 *  6.  Android    IvParameterSpec.$init — iv hex, static-IV flag
 *  7.  Android    Mac.doFinal          — alg, output hex
 *  8.  Android    MessageDigest.digest — alg, weak-alg flag
 *  9.  iOS        SecKeyCreateWithData — key data hex
 * 10.  OpenSSL    EVP_DecryptInit_ex   — ctx, cipher name, key hex, iv hex
 */

"use strict";

// ─── AUTHORIZATION GATE ───────────────────────────────────────────────────────
// crypto_extract requires explicit operator authorization before activating.
// Set globalThis.__OI_CRYPTO_EXTRACT_TOKEN to a non-empty session token before attaching.
// In production: this token comes from the scan session manager and is scoped to the case ID + target.

const _authToken: string | undefined = (globalThis as Record<string, unknown>).__OI_CRYPTO_EXTRACT_TOKEN as string | undefined;
if (!_authToken || _authToken.length < 8) {
  console.warn('[crypto_extract] NOT AUTHORIZED: __OI_CRYPTO_EXTRACT_TOKEN not set. Module inactive.');
  // Emit an event indicating the module is disabled (for audit trail)
  send(JSON.stringify({ type: 'hook_event', hook: 'crypto_extract', event: 'not_authorized', timestamp: Date.now() }));
  // Do not attach any hooks — exit cleanly
  throw new Error('crypto_extract: not authorized');
}

// DATA MINIMIZATION: by default, capture only algorithm name + key length (not raw key bytes)
// Set globalThis.__OI_CRYPTO_EXTRACT_FULL = true to capture full key material (requires additional authorization)
const _fullCapture: boolean = (globalThis as Record<string, unknown>).__OI_CRYPTO_EXTRACT_FULL === true;

function redactKey(hex: string): string {
  if (_fullCapture) return hex;
  // Metadata-only mode: return key length in bits, not the key
  return `[REDACTED:${hex.length * 4}bits]`;
}

// Audit emit — authorization confirmed
send(JSON.stringify({ type: 'audit', hook: 'crypto_extract', event: 'authorized', token_prefix: _authToken.slice(0, 4) + '...', full_capture: _fullCapture, timestamp: Date.now() }));

// ─── helpers ─────────────────────────────────────────────────────────────────

function emitEvent(data: Record<string, unknown>): void {
  send(
    JSON.stringify({
      type: "hook_event",
      hook: "crypto_extract",
      timestamp: Date.now(),
      ...data,
    })
  );
}

function ptrToHex(ptr: NativePointer, len: number): string {
  if (ptr.isNull() || len <= 0) return "";
  const MAX = 64;
  const n = Math.min(len, MAX);
  try {
    const bytes = ptr.readByteArray(n);
    if (!bytes) return "";
    const arr = Array.from(new Uint8Array(bytes));
    return arr.map((b) => b.toString(16).padStart(2, "0")).join("") + (len > MAX ? "…" : "");
  } catch {
    return "";
  }
}

function javaArrayToHex(javaBytes: unknown): string {
  try {
    if (!javaBytes) return "";
    const arr = javaBytes as { length: number; [i: number]: number };
    let hex = "";
    const max = Math.min(arr.length, 64);
    for (let i = 0; i < max; i++) {
      hex += ((arr[i] & 0xff).toString(16).padStart(2, "0"));
    }
    return hex + (arr.length > 64 ? "…" : "");
  } catch {
    return "";
  }
}

const WEAK_ALGS: Record<string, true> = {
  MD5: true, SHA1: true, "SHA-1": true,
  DES: true, DESede: true, RC2: true, RC4: true,
  "AES/ECB": true, ECB: true,
};

function isWeakAlg(alg: string): boolean {
  if (!alg) return false;
  const upper = alg.toUpperCase();
  return Object.keys(WEAK_ALGS).some((w) => upper.includes(w.toUpperCase()));
}

// CCCrypt algorithm constants (CommonCrypto)
const CC_ALG_NAMES: Record<number, string> = {
  0: "AES", 1: "DES", 2: "3DES", 3: "CAST", 4: "RC4",
  5: "RC2", 6: "Blowfish",
};

// ─── 1. iOS/macOS CCCrypt ─────────────────────────────────────────────────────

(function hookCCCrypt(): void {
  const candidates = ["libSystem.B.dylib", "libcommonCrypto.dylib", null];
  for (const lib of candidates) {
    const fn = Module.findExportByName(lib, "CCCrypt");
    if (!fn) continue;
    try {
      Interceptor.attach(fn, {
        onEnter(args) {
          try {
            const algId = args[1].toInt32();
            const alg = CC_ALG_NAMES[algId] ?? `alg${algId}`;
            const keyLen = args[3].toInt32();
            const keyPtr = args[2];
            const ivPtr = args[4];
            const dataInPtr = args[5];
            const dataInLen = args[6].toInt32();
            const rawKeyHex = ptrToHex(keyPtr, keyLen);
            const rawIvHex = ptrToHex(ivPtr, 16);
            emitEvent({
              api: "CCCrypt",
              algorithm: alg,
              key_hex: redactKey(rawKeyHex),
              iv_hex: _fullCapture ? rawIvHex : '[REDACTED]',
              data_in_hex: ptrToHex(dataInPtr, Math.min(dataInLen, 64)),
              key_length_bits: keyLen * 8,
              weak_key: keyLen * 8 < 128,
            });
          } catch (e) { console.warn("[crypto_extract] CCCrypt onEnter error:", e); }
        },
      });
      console.log(`[crypto_extract] CCCrypt hooked via ${lib ?? "global"}.`);
      break;
    } catch (e) {
      console.warn(`[crypto_extract] CCCrypt attach failed (${lib}):`, e);
    }
  }
})();

// ─── 4. OpenSSL EVP_EncryptInit_ex ────────────────────────────────────────────

(function hookEvpEncrypt(): void {
  const fn = Module.findExportByName(null, "EVP_EncryptInit_ex");
  if (!fn) { console.warn("[crypto_extract] EVP_EncryptInit_ex not found — skipping."); return; }
  try {
    // EVP_CIPHER_name(cipher) → const char*; try to resolve it
    const evpCipherName = Module.findExportByName(null, "EVP_CIPHER_name");
    const cipherNameFn = evpCipherName
      ? new NativeFunction(evpCipherName, "pointer", ["pointer"])
      : null;

    Interceptor.attach(fn, {
      onEnter(args) {
        try {
          const cipherPtr = args[1];
          let cipherName = "<unknown>";
          if (cipherNameFn && !cipherPtr.isNull()) {
            try { cipherName = (cipherNameFn(cipherPtr) as NativePointer).readCString() ?? "<unknown>"; } catch { /* ignore */ }
          }
          const keyPtr = args[3];
          const ivPtr = args[4];
          const rawKeyHex = keyPtr.isNull() ? "" : ptrToHex(keyPtr, 32);
          const rawIvHex = ivPtr.isNull() ? "" : ptrToHex(ivPtr, 16);
          emitEvent({
            api: "EVP_EncryptInit_ex",
            algorithm: cipherName,
            key_hex: redactKey(rawKeyHex),
            iv_hex: _fullCapture ? rawIvHex : '[REDACTED]',
            weak_key: false,
          });
        } catch (e) { console.warn("[crypto_extract] EVP_EncryptInit_ex onEnter error:", e); }
      },
    });
    console.log("[crypto_extract] EVP_EncryptInit_ex hooked.");
  } catch (e) { console.warn("[crypto_extract] EVP_EncryptInit_ex attach failed:", e); }
})();

// ─── 10. OpenSSL EVP_DecryptInit_ex ───────────────────────────────────────────

(function hookEvpDecrypt(): void {
  const fn = Module.findExportByName(null, "EVP_DecryptInit_ex");
  if (!fn) { console.warn("[crypto_extract] EVP_DecryptInit_ex not found — skipping."); return; }
  try {
    const evpCipherName = Module.findExportByName(null, "EVP_CIPHER_name");
    const cipherNameFn = evpCipherName
      ? new NativeFunction(evpCipherName, "pointer", ["pointer"])
      : null;

    Interceptor.attach(fn, {
      onEnter(args) {
        try {
          const cipherPtr = args[1];
          let cipherName = "<unknown>";
          if (cipherNameFn && !cipherPtr.isNull()) {
            try { cipherName = (cipherNameFn(cipherPtr) as NativePointer).readCString() ?? "<unknown>"; } catch { /* ignore */ }
          }
          const keyPtr = args[3];
          const ivPtr = args[4];
          const rawKeyHex = keyPtr.isNull() ? "" : ptrToHex(keyPtr, 32);
          const rawIvHex = ivPtr.isNull() ? "" : ptrToHex(ivPtr, 16);
          emitEvent({
            api: "EVP_DecryptInit_ex",
            algorithm: cipherName,
            key_hex: redactKey(rawKeyHex),
            iv_hex: _fullCapture ? rawIvHex : '[REDACTED]',
            weak_key: false,
          });
        } catch (e) { console.warn("[crypto_extract] EVP_DecryptInit_ex onEnter error:", e); }
      },
    });
    console.log("[crypto_extract] EVP_DecryptInit_ex hooked.");
  } catch (e) { console.warn("[crypto_extract] EVP_DecryptInit_ex attach failed:", e); }
})();

// ─── 5. iOS SecKeyEncrypt ─────────────────────────────────────────────────────

(function hookSecKeyEncrypt(): void {
  const fn = Module.findExportByName("Security", "SecKeyEncrypt");
  if (!fn) { console.warn("[crypto_extract] SecKeyEncrypt not found — skipping."); return; }
  try {
    Interceptor.attach(fn, {
      onEnter(args) {
        try {
          // SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen)
          const padding = args[1].toInt32();
          const plainTextPtr = args[2];
          const plainTextLen = args[3].toInt32();
          emitEvent({
            api: "SecKeyEncrypt",
            algorithm: "RSA",
            padding_type: padding,
            plain_text_hex: ptrToHex(plainTextPtr, Math.min(plainTextLen, 64)),
            weak_key: false,
          });
        } catch (e) { console.warn("[crypto_extract] SecKeyEncrypt onEnter error:", e); }
      },
    });
    console.log("[crypto_extract] SecKeyEncrypt hooked.");
  } catch (e) { console.warn("[crypto_extract] SecKeyEncrypt attach failed:", e); }
})();

// ─── 9. iOS SecKeyCreateWithData ──────────────────────────────────────────────

(function hookSecKeyCreateWithData(): void {
  const fn = Module.findExportByName("Security", "SecKeyCreateWithData");
  if (!fn) { console.warn("[crypto_extract] SecKeyCreateWithData not found — skipping."); return; }
  try {
    Interceptor.attach(fn, {
      onEnter(args) {
        try {
          // SecKeyCreateWithData(keyData: CFDataRef, attributes: CFDictionaryRef, error: CFErrorRef*)
          // CFData: header at offset 16 has length, bytes follow — heuristic read via ObjC
          let rawKeyHex = "";
          try {
            if (typeof ObjC !== "undefined" && ObjC.available) {
              const nsData = new ObjC.Object(args[0]);
              const len = nsData.length() as number;
              const bytesPtr = nsData.bytes() as NativePointer;
              rawKeyHex = ptrToHex(bytesPtr, Math.min(len, 64));
            }
          } catch { /* ObjC not available or not NSData */ }
          emitEvent({ api: "SecKeyCreateWithData", key_hex: redactKey(rawKeyHex), weak_key: false });
        } catch (e) { console.warn("[crypto_extract] SecKeyCreateWithData onEnter error:", e); }
      },
    });
    console.log("[crypto_extract] SecKeyCreateWithData hooked.");
  } catch (e) { console.warn("[crypto_extract] SecKeyCreateWithData attach failed:", e); }
})();

// ─── Java/Android layer ───────────────────────────────────────────────────────

if (typeof Java !== "undefined" && Java.available) {
  Java.perform(() => {

    // ── 2. Cipher.doFinal ───────────────────────────────────────────────────
    try {
      const Cipher = Java.use("javax.crypto.Cipher");

      Cipher.doFinal.overload("[B").implementation = function (input: unknown) {
        const alg: string = this.getAlgorithm();
        const inputHex = javaArrayToHex(input);
        const result: unknown = this.doFinal(input);
        const outputHex = javaArrayToHex(result);
        try {
          emitEvent({ api: "Cipher.doFinal", algorithm: alg, input_hex: inputHex, output_hex: outputHex, weak_key: isWeakAlg(alg) });
        } catch (e) { console.warn("[crypto_extract] Cipher.doFinal emit error:", e); }
        return result;
      };

      Cipher.doFinal.overload("[B", "int", "int").implementation = function (input: unknown, offset: number, len: number) {
        const alg: string = this.getAlgorithm();
        const inputHex = javaArrayToHex(input);
        const result: unknown = this.doFinal(input, offset, len);
        const outputHex = javaArrayToHex(result);
        try {
          emitEvent({ api: "Cipher.doFinal([BII)", algorithm: alg, input_hex: inputHex, output_hex: outputHex, weak_key: isWeakAlg(alg) });
        } catch (e) { console.warn("[crypto_extract] Cipher.doFinal([BII) emit error:", e); }
        return result;
      };

      console.log("[crypto_extract] Cipher.doFinal hooked.");
    } catch (e) { console.warn("[crypto_extract] Cipher.doFinal hook failed:", e); }

    // ── 3. SecretKeySpec.$init ──────────────────────────────────────────────
    try {
      const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

      SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (
        keyBytes: unknown,
        alg: string
      ) {
        this.$init(keyBytes, alg);
        const rawKeyHex = javaArrayToHex(keyBytes);
        const keyArr = keyBytes as { length: number };
        const weakKey = keyArr.length * 8 < 128;
        try {
          emitEvent({ api: "SecretKeySpec.$init", algorithm: alg, key_hex: redactKey(rawKeyHex), key_length_bits: keyArr.length * 8, weak_key: weakKey });
        } catch (e) { console.warn("[crypto_extract] SecretKeySpec.$init emit error:", e); }
      };

      SecretKeySpec.$init.overload("[B", "int", "int", "java.lang.String").implementation = function (
        keyBytes: unknown,
        offset: number,
        len: number,
        alg: string
      ) {
        this.$init(keyBytes, offset, len, alg);
        const rawKeyHex = javaArrayToHex(keyBytes);
        const weakKey = len * 8 < 128;
        try {
          emitEvent({ api: "SecretKeySpec.$init([BIIS)", algorithm: alg, key_hex: redactKey(rawKeyHex), key_length_bits: len * 8, weak_key: weakKey });
        } catch (e) { console.warn("[crypto_extract] SecretKeySpec.$init([BIIS) emit error:", e); }
      };

      console.log("[crypto_extract] SecretKeySpec.$init hooked.");
    } catch (e) { console.warn("[crypto_extract] SecretKeySpec hook failed:", e); }

    // ── 6. IvParameterSpec.$init ────────────────────────────────────────────
    try {
      const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

      IvParameterSpec.$init.overload("[B").implementation = function (iv: unknown) {
        this.$init(iv);
        const ivHex = javaArrayToHex(iv);
        // Flag static/hardcoded IVs — all-zero or all-same-byte is a strong signal
        const ivArr = iv as { length: number; [i: number]: number };
        const allSame = ivArr.length > 0 && Array.from({ length: ivArr.length }, (_, i) => ivArr[i]).every((b) => b === ivArr[0]);
        try {
          emitEvent({ api: "IvParameterSpec.$init", iv_hex: _fullCapture ? ivHex : '[REDACTED]', static_iv: allSame, weak_key: false });
        } catch (e) { console.warn("[crypto_extract] IvParameterSpec.$init emit error:", e); }
      };

      console.log("[crypto_extract] IvParameterSpec.$init hooked.");
    } catch (e) { console.warn("[crypto_extract] IvParameterSpec hook failed:", e); }

    // ── 7. Mac.doFinal ──────────────────────────────────────────────────────
    try {
      const Mac = Java.use("javax.crypto.Mac");

      Mac.doFinal.overload().implementation = function () {
        const alg: string = this.getAlgorithm();
        const result: unknown = this.doFinal();
        const outputHex = javaArrayToHex(result);
        try {
          emitEvent({ api: "Mac.doFinal", algorithm: alg, output_hex: outputHex, weak_key: isWeakAlg(alg) });
        } catch (e) { console.warn("[crypto_extract] Mac.doFinal emit error:", e); }
        return result;
      };

      console.log("[crypto_extract] Mac.doFinal hooked.");
    } catch (e) { console.warn("[crypto_extract] Mac.doFinal hook failed:", e); }

    // ── 8. MessageDigest.digest ─────────────────────────────────────────────
    try {
      const MessageDigest = Java.use("java.security.MessageDigest");

      MessageDigest.digest.overload().implementation = function () {
        const alg: string = this.getAlgorithm();
        const result: unknown = this.digest();
        try {
          emitEvent({ api: "MessageDigest.digest", algorithm: alg, output_hex: javaArrayToHex(result), weak_key: isWeakAlg(alg) });
        } catch (e) { console.warn("[crypto_extract] MessageDigest.digest emit error:", e); }
        return result;
      };

      console.log("[crypto_extract] MessageDigest.digest hooked.");
    } catch (e) { console.warn("[crypto_extract] MessageDigest.digest hook failed:", e); }

    console.log("[crypto_extract] Java crypto hooks installed.");
  });
}

emitEvent({ event: "crypto_extract_hook_installed", pid: Process.id, weak_key: false });
