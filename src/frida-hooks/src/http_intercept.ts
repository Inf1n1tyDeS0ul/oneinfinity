/**
 * http_intercept.ts — intercept HTTP before TLS
 * Targets: NSURLSession (iOS/macOS), XMLHttpRequest (all)
 *
 * NSURLSession: hooks -[NSURLSession dataTaskWithRequest:completionHandler:]
 * XHR: patches XMLHttpRequest.prototype.open in any Frida-accessible JS runtime
 */

"use strict";

// ─── NSURLSession (macOS / iOS) ───────────────────────────────────────────────

if (typeof ObjC !== "undefined" && ObjC.available) {
    try {
        const NSURLSessionClass = ObjC.classes["NSURLSession"];
        if (NSURLSessionClass) {
            const method = NSURLSessionClass["- dataTaskWithRequest:completionHandler:"];
            if (method) {
                Interceptor.attach(method.implementation, {
                    onEnter(args: InvocationArguments) {
                        try {
                            const request  = new ObjC.Object(args[2]);
                            const url      = request.URL().absoluteString().toString() as string;
                            const httpMethod = request.HTTPMethod().toString() as string;
                            send({
                                type:      "http_request",
                                framework: "NSURLSession",
                                url,
                                method:    httpMethod,
                                ts:        Date.now() / 1000,
                            });
                        } catch {
                            // skip if ObjC object not readable in this invocation
                        }
                    },
                });
            }
        }
    } catch {
        // not iOS/macOS or NSURLSession unavailable
    }
}

// ─── XMLHttpRequest (any Frida-accessible JS runtime) ────────────────────────

// Use the same globalThis cast pattern established in crypto_extract.ts
const _g = globalThis as Record<string, unknown>;

interface _XHRLike {
    prototype: {
        open(method: string, url: string, ...rest: unknown[]): void;
    };
}

function _isXHRLike(v: unknown): v is _XHRLike {
    return (
        typeof v === "function" &&
        v !== null &&
        "prototype" in v &&
        typeof (v as _XHRLike).prototype.open === "function"
    );
}

try {
    const XHR = _g["XMLHttpRequest"];
    if (_isXHRLike(XHR)) {
        const origOpen = XHR.prototype.open.bind(XHR.prototype) as (
            method: string,
            url: string,
            ...rest: unknown[]
        ) => void;

        XHR.prototype.open = function (
            this: unknown,
            method: string,
            url: string,
            ...rest: unknown[]
        ): void {
            send({
                type:      "http_request",
                framework: "XHR",
                url,
                method,
                ts:        Date.now() / 1000,
            });
            return origOpen.call(this, method, url, ...rest);
        };
    }
} catch {
    // no XHR in this runtime
}
