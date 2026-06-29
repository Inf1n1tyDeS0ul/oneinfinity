/**
 * objc_swizzle.ts — Objective-C method swizzling for SSL pinning bypass
 *
 * Hooks (macOS/iOS only; skipped entirely on non-ObjC platforms):
 *   1. NSURLSession delegate didReceiveChallenge — force-accept all TLS challenges
 *   2. SecTrustEvaluate            — always return errSecSuccess
 *   3. SecTrustEvaluateWithError   — always return true, clear error
 *
 * Exports ObjCSwizzler.swizzle() helper for caller-supplied swizzles.
 *
 * Emits NDJSON objc_swizzle_event records via send().
 */

"use strict";

// ─── guard ────────────────────────────────────────────────────────────────────

if (!ObjC.available) {
  send(
    JSON.stringify({
      type: "objc_swizzle_event",
      subtype: "skipped",
      reason: "ObjC runtime not available",
      pid: Process.id,
      timestamp: Date.now(),
    })
  );
  // Nothing more to do on a non-ObjC platform.
} else {
  // ─── helpers ───────────────────────────────────────────────────────────────

  function emitSwizzle(data: Record<string, unknown>): void {
    send(
      JSON.stringify({
        type: "objc_swizzle_event",
        pid: Process.id,
        timestamp: Date.now(),
        ...data,
      })
    );
  }

  // ─── public helper: ObjCSwizzler.swizzle ──────────────────────────────────

  /**
   * Replaces `className[-/+]selector` implementation with `replacement`.
   * Returns true on success; emits an objc_swizzle_event either way.
   *
   * @param className   - ObjC class name, e.g. "NSURLSession"
   * @param selector    - Frida-style selector, e.g. "- URLSession:didReceiveChallenge:completionHandler:"
   * @param replacement - NativeFunction or NativeCallback to install
   */
  function swizzle(
    className: string,
    selector: string,
    replacement: NativeFunction<unknown, unknown[]> | NativeCallback<unknown, unknown[]>
  ): boolean {
    try {
      const cls = ObjC.classes[className];
      if (!cls) {
        emitSwizzle({
          result: "error",
          target_class: className,
          selector,
          reason: "class not found",
        });
        return false;
      }
      const method = cls[selector];
      if (!method) {
        emitSwizzle({
          result: "error",
          target_class: className,
          selector,
          reason: "selector not found",
        });
        return false;
      }
      method.implementation = replacement;
      emitSwizzle({ result: "swizzled", target_class: className, selector });
      return true;
    } catch (err) {
      emitSwizzle({
        result: "error",
        target_class: className,
        selector,
        reason: String(err),
      });
      return false;
    }
  }

  // Export for callers who inject this script alongside others.
  (globalThis as Record<string, unknown>).ObjCSwizzler = { swizzle };

  // ─── NSURLSession: didReceiveChallenge ─────────────────────────────────────
  //
  // - URLSession:didReceiveChallenge:completionHandler:
  //   args: self, _cmd, session, challenge, completionHandler
  //
  // We call the completionHandler block with:
  //   NSURLSessionAuthChallengeUseCredential (0) + nil credential
  // which tells NSURLSession to proceed without verifying the cert.

  try {
    const NSURLSessionAuthChallengeUseCredential = 0;

    const didReceiveChallengeCallback = new ObjC.Block({
      retType: "void",
      argTypes: ["pointer", "pointer", "pointer", "pointer", "pointer"],
      implementation(
        _self: NativePointer,
        _cmd: NativePointer,
        _session: NativePointer,
        _challenge: NativePointer,
        completionHandler: NativePointer
      ) {
        try {
          const block = new ObjC.Block(completionHandler);
          block.implementation(NSURLSessionAuthChallengeUseCredential, NULL);
        } catch {
          // completionHandler call failed — best effort
        }
        emitSwizzle({
          result: "swizzled",
          target_class: "NSURLSessionDelegate",
          selector: "- URLSession:didReceiveChallenge:completionHandler:",
          subtype: "challenge_accepted",
        });
      },
    });

    // Swizzle on the protocol level: walk all loaded classes implementing the
    // delegate protocol and replace their implementation.
    const protocolName =
      "- URLSession:didReceiveChallenge:completionHandler:";

    let swizzledCount = 0;
    for (const className of Object.keys(ObjC.classes)) {
      try {
        const cls = ObjC.classes[className];
        if (cls && cls[protocolName]) {
          cls[protocolName].implementation =
            didReceiveChallengeCallback as unknown as NativeFunction<unknown, unknown[]>;
          swizzledCount++;
          emitSwizzle({
            result: "swizzled",
            target_class: className,
            selector: protocolName,
          });
        }
      } catch {
        // This class doesn't implement the selector — skip
      }
    }

    if (swizzledCount === 0) {
      emitSwizzle({
        result: "not_found",
        target_class: "NSURLSessionDelegate",
        selector: protocolName,
        reason: "no loaded classes implement this selector",
      });
    }
  } catch {
    emitSwizzle({
      result: "error",
      target_class: "NSURLSessionDelegate",
      selector: "- URLSession:didReceiveChallenge:completionHandler:",
      reason: "swizzle setup failed",
    });
  }

  // ─── SecTrustEvaluate ─────────────────────────────────────────────────────
  //
  // OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
  // errSecSuccess = 0, kSecTrustResultProceed = 1

  try {
    const secTrustEvalPtr = Module.findExportByName(
      null,
      "SecTrustEvaluate"
    );
    if (secTrustEvalPtr) {
      // OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
      const origImpl = new NativeFunction(secTrustEvalPtr, "int32", [
        "pointer",
        "pointer",
      ]);
      const replacement = new NativeCallback(
        function (trust: NativePointer, resultPtr: NativePointer): number {
          // Write kSecTrustResultProceed into the output parameter
          try {
            if (!resultPtr.isNull()) resultPtr.writeU32(1);
          } catch {
            // unwritable pointer — proceed anyway
          }
          void origImpl; // reference to prevent dead-code elimination
          emitSwizzle({
            result: "swizzled",
            target_class: "Security",
            selector: "SecTrustEvaluate",
            subtype: "forced_proceed",
          });
          return 0; // errSecSuccess
        },
        "int32",
        ["pointer", "pointer"]
      );
      Interceptor.replace(secTrustEvalPtr, replacement);
      emitSwizzle({
        result: "swizzled",
        target_class: "Security",
        selector: "SecTrustEvaluate",
      });
    } else {
      emitSwizzle({
        result: "not_found",
        target_class: "Security",
        selector: "SecTrustEvaluate",
      });
    }
  } catch {
    emitSwizzle({
      result: "error",
      target_class: "Security",
      selector: "SecTrustEvaluate",
    });
  }

  // ─── SecTrustEvaluateWithError ────────────────────────────────────────────
  //
  // bool SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error)
  // Returns true (trusted) when errSecSuccess; clear the CFErrorRef output.

  try {
    const secTrustEvalErrPtr = Module.findExportByName(
      null,
      "SecTrustEvaluateWithError"
    );
    if (secTrustEvalErrPtr) {
      const replacement = new NativeCallback(
        function (_trust: NativePointer, errorPtr: NativePointer): number {
          // Clear the CFErrorRef output so callers see no error
          try {
            if (!errorPtr.isNull()) errorPtr.writePointer(NULL);
          } catch {
            // unwritable pointer — proceed anyway
          }
          emitSwizzle({
            result: "swizzled",
            target_class: "Security",
            selector: "SecTrustEvaluateWithError",
            subtype: "forced_trusted",
          });
          return 1; // true — trust evaluation "succeeded"
        },
        "uint32",
        ["pointer", "pointer"]
      );
      Interceptor.replace(secTrustEvalErrPtr, replacement);
      emitSwizzle({
        result: "swizzled",
        target_class: "Security",
        selector: "SecTrustEvaluateWithError",
      });
    } else {
      emitSwizzle({
        result: "not_found",
        target_class: "Security",
        selector: "SecTrustEvaluateWithError",
      });
    }
  } catch {
    emitSwizzle({
      result: "error",
      target_class: "Security",
      selector: "SecTrustEvaluateWithError",
    });
  }

  emitSwizzle({ subtype: "objc_swizzle_installed" });
}
