//! `sorted_compact` against the serializers `lock` and `pack` use today, two ways:
//!
//! 1. identical documents through VERBATIM COPIES of their functions (below, with source commit)
//!    and through core: byte-identical;
//! 2. stored self-hashes in real artifacts (`lock_hash`, `pack_id`) that those tools computed.
//!
//! Also pins where this form differs from RFC 8785, so the two are never silently swapped.

use cmdrvl_core::hash::{Algorithm, hash_bytes};
use cmdrvl_core::{jcs, lockfile, sorted_compact};
use serde_json::{Map, Value, json};

// ── verbatim copy: lock src/lockfile/self_hash.rs @ 8c0cdd9ed03c8cdb77ac2c4559b96b5723f5f9aa ──

fn lock_canonical_json_with_top_level_lock_hash(
    value: &Value,
    lock_hash: &str,
) -> Result<String, serde_json::Error> {
    let mut bytes = Vec::new();
    match value {
        Value::Object(map) => {
            lock_write_canonical_object(map, &mut bytes, Some(lock_hash))?;
        }
        other => lock_write_canonical_value(other, &mut bytes)?,
    }
    Ok(String::from_utf8(bytes).expect("JSON serialization must emit UTF-8"))
}

fn lock_write_canonical_value(value: &Value, bytes: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    match value {
        Value::Object(map) => lock_write_canonical_object(map, bytes, None),
        Value::Array(array) => {
            bytes.push(b'[');
            for (index, item) in array.iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                lock_write_canonical_value(item, bytes)?;
            }
            bytes.push(b']');
            Ok(())
        }
        other => serde_json::to_writer(bytes, other),
    }
}

fn lock_write_canonical_object(
    map: &Map<String, Value>,
    bytes: &mut Vec<u8>,
    top_level_lock_hash: Option<&str>,
) -> Result<(), serde_json::Error> {
    let mut entries = map.iter().collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(key, _)| *key);

    bytes.push(b'{');
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index > 0 {
            bytes.push(b',');
        }
        serde_json::to_writer(&mut *bytes, key)?;
        bytes.push(b':');
        match top_level_lock_hash {
            Some(lock_hash) if key == "lock_hash" => serde_json::to_writer(&mut *bytes, lock_hash)?,
            _ => lock_write_canonical_value(value, bytes)?,
        }
    }
    bytes.push(b'}');
    Ok(())
}

fn lock_to_canonical_json(value: &Value) -> String {
    let mut bytes = Vec::new();
    lock_write_canonical_value(value, &mut bytes).expect("lock serializer");
    String::from_utf8(bytes).expect("utf-8")
}

// ── verbatim copy: pack src/seal/manifest.rs @ 1bd47d8b582b797ff2ad4bd13b4a726c6d8c61b2 ──

fn pack_sorted_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        pack_sorted_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let entries: Vec<String> = arr.iter().map(pack_sorted_json).collect();
            format!("[{}]", entries.join(","))
        }
        _ => serde_json::to_string(value).unwrap(),
    }
}

const SHA_LOCK: &str = include_str!("fixtures/lock_v0/sha256.lock.json");
const B3_LOCK: &str = include_str!("fixtures/lock_v0/blake3.lock.json");
const PACK_MANIFEST: &str = include_str!("fixtures/pack/valid/manifest.json");
const PACK_NOV_LOCK: &str = include_str!("fixtures/pack/valid/nov.lock.json");

fn documents() -> Vec<(String, Value)> {
    let mut documents: Vec<(String, Value)> = [
        ("spine-rules sha256 lock", SHA_LOCK),
        ("spine-rules blake3 lock", B3_LOCK),
        ("pack valid manifest", PACK_MANIFEST),
        ("pack nov lock", PACK_NOV_LOCK),
    ]
    .into_iter()
    .map(|(name, text)| (name.to_owned(), serde_json::from_str(text).expect(name)))
    .collect();
    // Hostile content the artifacts do not have: escapes, controls, non-ASCII and supplementary
    // characters in keys and values, floats, big integers, nesting, empties.
    let mut controls = String::new();
    for code in 0u32..0x20 {
        controls.push(char::from_u32(code).expect("control"));
    }
    documents.push((
        "hostile".to_owned(),
        json!({
            "z": [1, 1.0, -0.0, 1e21, 1e-7, 0.1, 333333333.3333333, 18446744073709551615u64, -9223372036854775808i64],
            "a": {"é": "€", "\u{fb33}": "dalet", "\u{1f600}": "emoji", "\"q\"": "back\\slash/", "": null},
            "c": controls,
            "\u{7f}": [[], {}, true, false, {"lock_hash": "nested stays"}],
            "A": "upper sorts before lower"
        }),
    ));
    for (name, text) in [
        ("scalar string", "\"x\""),
        ("array", "[3,2,1]"),
        ("number", "2.5"),
    ] {
        documents.push((name.to_owned(), serde_json::from_str(text).expect(name)));
    }
    documents
}

#[test]
fn sorted_compact_is_byte_identical_to_lock_and_pack_serializers() {
    let documents = documents();
    assert!(documents.len() >= 8);
    for (name, document) in &documents {
        let core = sorted_compact::to_string(document);
        assert_eq!(core, lock_to_canonical_json(document), "lock: {name}");
        assert_eq!(core, pack_sorted_json(document), "pack: {name}");
        assert_eq!(
            sorted_compact::to_vec(document),
            core.into_bytes(),
            "{name}"
        );
    }
}

#[test]
fn compute_lock_hash_is_byte_identical_to_lock_with_the_top_level_hash_blanked() {
    for (name, document) in documents() {
        let expected =
            lock_canonical_json_with_top_level_lock_hash(&document, "").expect("lock serializer");
        assert_eq!(
            lockfile::compute_lock_hash(&document),
            hash_bytes(Algorithm::Sha256, expected.as_bytes()),
            "{name}"
        );
    }
    // Only the TOP-LEVEL member is blanked.
    let nested = json!({"lock_hash": "x", "inner": {"lock_hash": "keep"}});
    let changed = json!({"lock_hash": "x", "inner": {"lock_hash": "other"}});
    assert_ne!(
        lockfile::compute_lock_hash(&nested),
        lockfile::compute_lock_hash(&changed)
    );
    let other_top = json!({"lock_hash": "y", "inner": {"lock_hash": "keep"}});
    assert_eq!(
        lockfile::compute_lock_hash(&nested),
        lockfile::compute_lock_hash(&other_top)
    );
}

#[test]
fn stored_lock_hashes_of_real_lock_output_verify() {
    for (name, text) in [("sha256 lock", SHA_LOCK), ("blake3 lock", B3_LOCK)] {
        let lock: Value = serde_json::from_str(text).expect(name);
        assert!(lock["lock_hash"].is_string(), "{name}");
        assert!(
            lockfile::verify_lock_hash(&lock),
            "{name}: stored lock_hash"
        );
        let mut tampered = lock.clone();
        tampered["members"][0]["path"] = json!("tampered.csv");
        assert!(
            !lockfile::verify_lock_hash(&tampered),
            "{name}: tamper detected"
        );
    }
    assert!(!lockfile::verify_lock_hash(&json!({"version": "lock.v0"})));
}

#[test]
fn stored_pack_id_of_pack_fixture_is_reproduced() {
    let manifest: Value = serde_json::from_str(PACK_MANIFEST).expect("manifest");
    let stored = manifest["pack_id"].as_str().expect("pack_id").to_owned();
    let mut blanked = manifest;
    blanked["pack_id"] = json!("");
    assert_eq!(
        hash_bytes(Algorithm::Sha256, &sorted_compact::to_vec(&blanked)),
        stored
    );
}

#[test]
fn jcs_equals_sorted_compact_on_the_real_artifacts_but_not_in_general() {
    // On these artifacts (ASCII keys, integers and strings) the two forms agree...
    for text in [SHA_LOCK, B3_LOCK, PACK_MANIFEST, PACK_NOV_LOCK] {
        let value: Value = serde_json::from_str(text).expect("artifact");
        assert_eq!(
            jcs::to_string(&value).expect("jcs"),
            sorted_compact::to_string(&value)
        );
    }
    // ...planted negative 1: key order. U+1F600 is a surrogate pair (D83D DE00), so UTF-16 order
    // puts it before U+FB33; UTF-8 / code point order puts it after.
    let keys = json!({"\u{fb33}": 1, "\u{1f600}": 2});
    assert_eq!(
        sorted_compact::to_string(&keys),
        "{\"\u{fb33}\":1,\"\u{1f600}\":2}"
    );
    assert_eq!(
        jcs::to_string(&keys).expect("jcs"),
        "{\"\u{1f600}\":2,\"\u{fb33}\":1}"
    );
    // ...planted negative 2: number text.
    let numbers = json!([1.0, 100.0]);
    assert_eq!(sorted_compact::to_string(&numbers), "[1.0,100.0]");
    assert_eq!(jcs::to_string(&numbers).expect("jcs"), "[1,100]");
}
