/**
 * memory_search.ts — scan process heap for secret patterns
 * Detects: JWT tokens, AWS access keys, API tokens, session cookies,
 *          JWT HS256 secrets, bcrypt hashes, PEM private-key headers,
 *          Android KeyStore alias names
 * Emits one send() call per match: {type: 'memory_match', pattern: string, offset: string, preview: string}
 */

"use strict";

// Convert ASCII string to Frida Memory.scanSync hex byte pattern ("41 42 43")
function asciiToPattern(s: string): string {
    const parts: string[] = [];
    for (let i = 0; i < s.length; i++) {
        parts.push(s.charCodeAt(i).toString(16).padStart(2, "0"));
    }
    return parts.join(" ");
}

// Patterns to search — converted to Frida hex byte patterns at hook install time
const SECRET_PATTERNS: Array<{ name: string; pattern: string }> = [
    // ── existing patterns ─────────────────────────────────────────────────────
    { name: "jwt",           pattern: asciiToPattern("eyJ")              }, // JWT header prefix
    { name: "aws_key",       pattern: asciiToPattern("AKIA")             }, // AWS access key
    { name: "api_token",     pattern: asciiToPattern("Bearer ")          }, // Bearer token prefix
    { name: "session",       pattern: asciiToPattern("session_id=")      }, // session cookie
    { name: "github_pat",    pattern: asciiToPattern("ghp_")             }, // GitHub PAT
    { name: "openai_key",    pattern: asciiToPattern("sk-")              }, // OpenAI API key
    { name: "slack_bot",     pattern: asciiToPattern("xoxb-")            }, // Slack bot token
    { name: "sendgrid",      pattern: asciiToPattern("SG.")              }, // SendGrid key
    { name: "stripe_live",   pattern: asciiToPattern("pk_live_")         }, // Stripe live key
    { name: "private_key",   pattern: asciiToPattern("private_key")      }, // generic private key
    { name: "password_form", pattern: asciiToPattern("password=")        }, // form POST data
    { name: "auth_header",   pattern: asciiToPattern("Authorization:")   }, // auth header in memory
    { name: "token_field",   pattern: asciiToPattern("token")            }, // generic token field
    // ── JWT HS256 secret detection ────────────────────────────────────────────
    // A base64url-encoded HMAC secret sitting before the second "." of a JWT;
    // look for a dot following 43+ base64url chars (32-byte secret → 43 chars)
    { name: "jwt_hs256_secret", pattern: asciiToPattern("HS256")         }, // alg claim in header
    // ── bcrypt hash patterns ──────────────────────────────────────────────────
    { name: "bcrypt_2b",     pattern: asciiToPattern("$2b$")             }, // bcrypt cost-factor prefix
    { name: "bcrypt_2a",     pattern: asciiToPattern("$2a$")             }, // bcrypt legacy prefix
    { name: "bcrypt_2y",     pattern: asciiToPattern("$2y$")             }, // bcrypt PHP prefix
    // ── PEM private-key headers ───────────────────────────────────────────────
    { name: "pem_rsa_key",   pattern: asciiToPattern("-----BEGIN RSA PRIVATE KEY-----")     },
    { name: "pem_ec_key",    pattern: asciiToPattern("-----BEGIN EC PRIVATE KEY-----")      },
    { name: "pem_priv_key",  pattern: asciiToPattern("-----BEGIN PRIVATE KEY-----")         },
    { name: "pem_pub_key",   pattern: asciiToPattern("-----BEGIN PUBLIC KEY-----")          },
    { name: "pem_cert",      pattern: asciiToPattern("-----BEGIN CERTIFICATE-----")         },
    // ── Android KeyStore alias names ──────────────────────────────────────────
    // KeyStore aliases are plain strings passed to KeyStore.getEntry(alias, ...)
    // Common alias prefixes used by Android apps and the platform itself
    { name: "keystore_alias_android", pattern: asciiToPattern("AndroidKeyStore")            },
    { name: "keystore_alias_key",     pattern: asciiToPattern("alias")                      },
    { name: "keystore_entry",         pattern: asciiToPattern("KeyStore.getInstance")        },
];

const CHUNK_BYTES  = 1024 * 1024; // 1 MB scan chunks for large regions
const PREVIEW_LEN  = 32;
const READ_LEN     = 128;

function scanRegion(base: NativePointer, size: number): void {
    SECRET_PATTERNS.forEach(({ name, pattern }) => {
        try {
            const matches = Memory.scanSync(base, size, pattern);
            matches.forEach((match: MemoryScanMatch) => {
                let preview = "";
                try {
                    preview = match.address.readUtf8String(Math.min(READ_LEN, size)) ?? "";
                } catch {
                    // unreadable as UTF-8 — leave preview empty
                }
                send({
                    type:    "memory_match",
                    pattern: name,
                    offset:  match.address.toString(),
                    preview: preview.substring(0, PREVIEW_LEN),
                });
            });
        } catch {
            // skip unreadable or inaccessible ranges
        }
    });
}

// Scan all readable memory ranges; chunk large regions to avoid Frida limits
Process.enumerateRanges("r--").forEach((range: RangeDetails) => {
    if (range.size <= CHUNK_BYTES) {
        scanRegion(range.base, range.size);
    } else {
        // Iterate through the region in CHUNK_BYTES slices
        let offset = 0;
        while (offset < range.size) {
            const chunkSize = Math.min(CHUNK_BYTES, range.size - offset);
            scanRegion(range.base.add(offset), chunkSize);
            offset += chunkSize;
        }
    }
});
