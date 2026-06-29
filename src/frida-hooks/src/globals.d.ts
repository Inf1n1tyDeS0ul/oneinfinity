/**
 * globals.d.ts — ambient declarations for globals Frida provides at runtime
 * that @types/frida-gum does not declare.
 *
 * Frida injects a console shim into every script's runtime.  Declaring it here
 * lets TypeScript accept console.log / console.warn / console.error in all hooks
 * without pulling in DOM or @types/node lib files.
 */

declare const console: {
    log(...args: unknown[]): void;
    warn(...args: unknown[]): void;
    error(...args: unknown[]): void;
    info(...args: unknown[]): void;
    debug(...args: unknown[]): void;
};
