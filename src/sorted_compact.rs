//! The "sorted compact JSON" that `lock` (`src/lockfile/self_hash.rs`, commit 8c0cdd9) and
//! `pack` (`src/seal/manifest.rs`, commit 1bd47d8) hash today: object keys sorted by Rust string
//! order (UTF-8 bytes, which is code point order) at every level, no insignificant whitespace, no
//! trailing newline, and serde_json's own text for strings and numbers.
//!
//! **This is not RFC 8785.** It differs from [`crate::jcs`] when member names mix characters in
//! U+E000..=U+FFFF with characters above U+FFFF (JCS sorts by UTF-16 code units), and for numbers
//! serde_json writes differently from ECMAScript (`1.0` here, `1` in JCS). Stored `lock_hash` and
//! `pack_id` values depend on exactly these bytes, so moving a tool to JCS would change its
//! hashes. Use [`crate::jcs`] for new third-party-recomputable hashes.
//!
//! Keys are sorted here explicitly, so the output does not depend on whether a consumer enables
//! serde_json's `preserve_order` feature.

use serde_json::Value;

/// The sorted compact form of `value`.
pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// [`to_string`] as UTF-8 bytes.
pub fn to_vec(value: &Value) -> Vec<u8> {
    to_string(value).into_bytes()
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (index, (name, member)) in members.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_scalar(out, &Value::String(name.clone()));
                out.push(':');
                write_value(out, member);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        scalar => write_scalar(out, scalar),
    }
}

/// Strings, numbers, booleans and null exactly as serde_json prints them.
fn write_scalar(out: &mut String, scalar: &Value) {
    // Serializing a scalar `Value` cannot fail: no map keys, no non-finite numbers.
    out.push_str(&serde_json::to_string(scalar).expect("a JSON scalar serializes"));
}
