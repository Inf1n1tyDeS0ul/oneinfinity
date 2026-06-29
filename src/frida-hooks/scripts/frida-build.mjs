#!/usr/bin/env node
// frida-build.mjs — wrapper for frida-compile on paths containing spaces.
//
// frida-compile 17.x derives its lib path via import.meta.url, which Node
// URL-encodes spaces to %20.  crosspath.urlToFilename does NOT decode %20,
// so TypeScript cannot find lib.es2020.d.ts on such paths.
//
// Fix: copy the entire hooks directory to a space-free tmpdir, invoke the
// frida-compile cli.js from there via `node <explicit-path>` (bypassing the
// .bin symlink, whose shebang resolution can re-introduce the original path),
// then copy the compiled output back.

import { execFileSync }      from "node:child_process";
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir }            from "node:os";
import { fileURLToPath }     from "node:url";
import { randomBytes }       from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));

// CLI: node scripts/frida-build.mjs <input.ts relative to src/> <output.js relative to dist/>
// e.g.:  node scripts/frida-build.mjs src/memory_search.ts dist/memory_search.js
const [inputRel, outputRel] = process.argv.slice(2);
if (!inputRel || !outputRel) {
  process.stderr.write("Usage: frida-build.mjs <input.ts> <output.js>\n");
  process.exit(1);
}

// projectDir = the frida-hooks/ directory (may contain spaces)
const projectDir = resolve(__dirname, "..");

// Space-free temp working copy
const tag    = randomBytes(4).toString("hex");
const tmpDir = join(tmpdir(), `oi-frida-${tag}`);

cpSync(projectDir, tmpDir, { recursive: true });

// Run `node <explicit-cli-path> <input> -o <output>` from the space-free tmpDir.
// Using the explicit .js path (not the .bin/ symlink) ensures Node sets
// import.meta.url to the temp-dir path, which has no spaces.
const cliJs = join(tmpDir, "node_modules", "frida-compile", "dist", "cli.js");
mkdirSync(join(tmpDir, dirname(outputRel)), { recursive: true });

execFileSync(process.execPath, [cliJs, inputRel, "-o", outputRel], {
  cwd:   tmpDir,
  stdio: "inherit",
});

// Copy output back to the real project
const realOut = join(projectDir, outputRel);
mkdirSync(dirname(realOut), { recursive: true });
writeFileSync(realOut, readFileSync(join(tmpDir, outputRel)));

console.log(`[frida-build] ${outputRel} written`);
