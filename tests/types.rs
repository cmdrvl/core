//! `hash`, `contract` and `refusal`. Digest literals were computed outside this crate with
//! `openssl dgst -sha256` and `b3sum`.

use cmdrvl_core::contract::ContractHash;
use cmdrvl_core::hash::{Algorithm, HashError, hash_bytes, parse_prefixed};
use cmdrvl_core::refusal::{Envelope, ExitCode, Refusal};
use serde_json::json;

// printf '%s' abc | openssl dgst -sha256
const SHA_ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
// printf '%s' abc | b3sum
const B3_ABC: &str = "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";

#[test]
fn hash_bytes_matches_external_tools() {
    assert_eq!(hash_bytes(Algorithm::Sha256, b"abc"), SHA_ABC);
    assert_eq!(hash_bytes(Algorithm::Blake3, b"abc"), B3_ABC);
}

#[test]
fn parse_prefixed_accepts_only_a_known_prefix_and_64_lowercase_hex() {
    assert_eq!(
        parse_prefixed(SHA_ABC).expect("sha256").0,
        Algorithm::Sha256
    );
    assert_eq!(
        parse_prefixed(B3_ABC).expect("blake3"),
        (Algorithm::Blake3, &B3_ABC[7..])
    );
    for unknown in ["md5:00", "ba7816bf", "", "SHA256:ab", "blake2:ab"] {
        assert_eq!(
            parse_prefixed(unknown),
            Err(HashError::UnknownAlgorithm),
            "{unknown}"
        );
    }
    let hex = &SHA_ABC[7..];
    for bad in [
        "sha256:".to_owned(),
        format!("sha256:{}", &hex[..63]),
        format!("sha256:{hex}0"),
        format!("sha256:{}", hex.to_uppercase()),
        format!("sha256:{}g", &hex[..63]),
        format!("blake3:{} ", &hex[..63]),
    ] {
        assert_eq!(parse_prefixed(&bad), Err(HashError::BadDigest), "{bad}");
    }
    // The lock verifier's lenient reading stays prefix-only.
    assert_eq!(Algorithm::of("sha256:zz"), Some(Algorithm::Sha256));
}

#[test]
fn contract_hash_is_blake3_over_jcs_and_parses_strictly() {
    // printf '%s' '{"a":1,"b":[true,null]}' | b3sum   (the RFC 8785 text of the value below)
    let expected = "blake3:1fb9c58b4f400e362936d1c5be0ee7b2369bcd03f9c923bc2b8c716517716e00";
    let value = json!({"b": [true, null], "a": 1.0});
    let hash = ContractHash::of_jcs(&value).expect("hashable");
    assert_eq!(hash.as_str(), expected);
    assert_eq!(hash.to_string(), expected);
    assert_eq!(ContractHash::parse(expected).expect("round trip"), hash);
    assert_eq!(ContractHash::parse("blake3:abc"), Err(HashError::BadDigest));
    assert_eq!(
        ContractHash::parse("md5:abc"),
        Err(HashError::UnknownAlgorithm)
    );
    assert!(ContractHash::of_jcs(&json!(u64::MAX)).is_err());
}

#[test]
fn exit_codes_are_the_family_dictionary() {
    for (code, number) in [
        (ExitCode::Positive, 0),
        (ExitCode::Negative, 1),
        (ExitCode::Refusal, 2),
        (ExitCode::Policy, 3),
    ] {
        assert_eq!(code.code(), number);
    }
}

#[test]
fn refusal_envelope_prints_sorted_compact_json_without_a_newline() {
    let envelope = Envelope::new(
        "lock.v0",
        Refusal {
            code: "E_EMPTY".to_owned(),
            message: "no input records".to_owned(),
            detail: json!({"z": 1, "a": {"y": 2, "b": 3}}),
            next_command: None,
        },
    );
    // The text lock's RefusalEnvelope::to_json prints: every level sorted, null kept.
    assert_eq!(
        envelope.to_json(),
        r#"{"outcome":"REFUSAL","refusal":{"code":"E_EMPTY","detail":{"a":{"b":3,"y":2},"z":1},"message":"no input records","next_command":null},"version":"lock.v0"}"#
    );
    assert_eq!(envelope.exit_code(), ExitCode::Refusal);
}
