/**
 * jni_trace.ts — trace JNI boundary calls
 * Intercepts FindClass, GetMethodID, GetStaticMethodID, CallObjectMethod,
 * CallStaticObjectMethod to map native lib → Java bridge on Android.
 *
 * Java.vm.getEnv() returns a Frida Env wrapper whose JNI function-table entries
 * are exposed as own properties under their JNI camelCase names.  We look up each
 * function by name at runtime; the cast to Record<string, NativePointer|undefined>
 * is intentional — frida-gum typings do not enumerate every JNI slot.
 */

"use strict";

const JNI_FNS: readonly string[] = [
    "FindClass",
    "GetMethodID",
    "GetStaticMethodID",
    "CallObjectMethod",
    "CallStaticObjectMethod",
];

const MAX_NAME_LEN = 255;

if (typeof Java !== "undefined" && Java.available) {
    try {
        const jni_env = Java.vm.getEnv();
        // frida-gum does not enumerate JNI slots in its Env type;
        // cast once here — NativePointer | undefined per slot is the narrowest safe type.
        const env_table = jni_env as unknown as Record<string, NativePointer | undefined>;

        JNI_FNS.forEach((fn_name: string) => {
            try {
                const fn_ptr: NativePointer | undefined = env_table[fn_name];
                if (!fn_ptr || fn_ptr.isNull()) return;

                Interceptor.attach(fn_ptr, {
                    onEnter(args: InvocationArguments) {
                        // args[1] is typically the class or method name C-string
                        try {
                            const name: string | null = args[1].readCString();
                            if (
                                name !== null &&
                                name.length > 0 &&
                                name.length <= MAX_NAME_LEN
                            ) {
                                send({
                                    type: "jni_call",
                                    fn:   fn_name,
                                    arg:  name,
                                    ts:   Date.now() / 1000,
                                });
                            }
                        } catch {
                            // unreadable pointer — skip this invocation
                        }
                    },
                });
            } catch {
                // fn_name not available in this JNI env — skip
            }
        });
    } catch {
        // Java.vm.getEnv() unavailable — not an Android target
    }
}
