//! Redactor known answers. Every expected hex value is a LITERAL computed outside this crate
//! (openssl, as shown), or copied from a tool's own openssl-checked test (source named). Nothing
//! here derives an expectation from the code under test.

use cmdrvl_core::redact::{
    FALLBACK_ENV, KeyError, Marker, Namespace, RedactionKey, Scheme, frame_components, select_key,
};

fn key(text: &str) -> RedactionKey {
    RedactionKey::new(text.as_bytes().to_vec()).expect("usable key")
}

fn full(hex32: &str) -> String {
    format!("redacted:hmac-sha256:{hex32}")
}

const ORCHESTRATOR_KEY: &str = "0123456789abcdef0123";

// printf '%s' CANARYCOL | openssl dgst -sha256 -hmac 0123456789abcdef0123
// printf '%s' 77        | openssl dgst -sha256 -hmac 0123456789abcdef0123
// printf '\x0a\x00\x00\x00\x00\x00\x00\x00KEYCANARY1' | openssl dgst -sha256 -hmac 0123456789abcdef0123
#[test]
fn raw_scheme_matches_rvl_column_value_and_framed_row_key() {
    let key = key(ORCHESTRATOR_KEY);
    let mut marker = Marker::keyed(&key, Scheme::Raw);
    assert_eq!(
        marker.mark(Namespace::COLUMN, b"CANARYCOL"),
        full("df881a3e5d888c2312970dd2847f32b2")
    );
    assert_eq!(
        marker.mark(Namespace::VALUE, b"77"),
        full("afba9fe047e677b4e0bbc565f5b21000")
    );
    assert_eq!(
        marker.mark(Namespace::ROW, &frame_components(&["KEYCANARY1"])),
        full("cde146933bb8e2405588e79f82c81a24")
    );
}

// rvl tests/refusal_redaction.rs and src/redaction.rs (openssl, key 0123456789abcdef).
#[test]
fn raw_scheme_matches_rvls_own_known_answers() {
    let key = key("0123456789abcdef");
    for (input, expected) in [
        (b"open".to_vec(), "b0dd9e34e5ee47920ba0efa2d9a3e5be"),
        (b"closed".to_vec(), "1fa915cc3c47c712fd41242d017fb1cf"),
        (b"7777123".to_vec(), "6f34db1038ebf91f70eda4e26e376864"),
        (b"COLCANARY".to_vec(), "e132ce51215d63c4642d82f8f78b6046"),
        (
            frame_components(&["KEYCANARY-77"]),
            "779b738c46bd51be4af111c5690bec8a",
        ),
    ] {
        assert_eq!(key.marker_raw(&input), full(expected));
    }
}

// printf 'column\0zeta_newcanary' | openssl dgst -sha256 -hmac 0123456789abcdef0123
// printf 'column\0loan_id'        | openssl dgst -sha256 -hmac 0123456789abcdef   (profile)
// printf 'column\0NEWCOL-Zq9x-7f2e' / 'column\0Canary-Loan-ID' (profile tests/evolve_redaction.rs)
#[test]
fn tagged_scheme_matches_profile_and_fingerprint() {
    let key20 = key(ORCHESTRATOR_KEY);
    assert_eq!(
        Marker::keyed(&key20, Scheme::Tagged).mark(Namespace::COLUMN, b"zeta_newcanary"),
        full("4fefcade206b2d175d9558dd46494231")
    );
    let key16 = key("0123456789abcdef");
    for (name, expected) in [
        ("loan_id", "9f6181c104894742edc83d76f18dc14f"),
        ("NEWCOL-Zq9x-7f2e", "599db4f123b40c03552a06a3336c2a4d"),
        ("Canary-Loan-ID", "4afa987e0bb7f7fd09b022400524387d"),
    ] {
        assert_eq!(
            key16.marker_tagged("column", name.as_bytes()),
            full(expected)
        );
    }
}

// verify tests/redaction.rs and crates/verify-cli/src/redact.rs: HMAC over the serde_json TEXT of
// the value (a string includes its quotes).
#[test]
fn raw_scheme_over_json_text_matches_verify() {
    let key = key("0123456789abcdef");
    for (value, expected) in [
        ("CANARY-KEY-7f3a91", "32dceb15d63e18d75268bf4d7b813cdf"),
        ("CANARY-CELL-c2d8e4", "0dd139a43c5c4a0d7ae4619dde84bcec"),
        ("CANARY-CELL-77c2d4", "f90d3ee3380b0597dd4632a72c956056"),
    ] {
        let text = serde_json::to_string(&serde_json::json!(value)).expect("json");
        assert_eq!(key.marker_raw(text.as_bytes()), full(expected));
    }
}

#[test]
fn the_two_schemes_differ_and_neither_can_stand_in_for_the_other() {
    // The planted negative for scheme confusion: the same key, namespace and bytes.
    let key = key(ORCHESTRATOR_KEY);
    let raw = Marker::keyed(&key, Scheme::Raw).mark(Namespace::COLUMN, b"zeta_newcanary");
    let tagged = Marker::keyed(&key, Scheme::Tagged).mark(Namespace::COLUMN, b"zeta_newcanary");
    // printf '%s' zeta_newcanary | openssl dgst -sha256 -hmac 0123456789abcdef0123
    assert_eq!(raw, full("56b1579144b5ac2e81c3a207c513808c"));
    assert_ne!(raw, tagged);
    // Raw has no domain separation; Tagged does.
    assert_eq!(
        key.marker_raw(b"x"),
        Marker::keyed(&key, Scheme::Raw).mark(Namespace::PATH, b"x")
    );
    assert_ne!(
        key.marker_tagged(Namespace::COLUMN.tag, b"x"),
        key.marker_tagged(Namespace::PATH.tag, b"x")
    );
}

#[test]
fn framing_keeps_different_tuples_different_and_unframed_bytes_do_not_match() {
    assert_ne!(
        frame_components(&["ab", "c"]),
        frame_components(&["a", "bc"])
    );
    let key = key(ORCHESTRATOR_KEY);
    assert_ne!(
        key.marker_raw(b"KEYCANARY1"),
        full("cde146933bb8e2405588e79f82c81a24"),
        "an unframed key must not reproduce the framed marker"
    );
}

#[test]
fn empty_and_short_keys_are_refused_and_sixteen_bytes_is_accepted() {
    assert_eq!(RedactionKey::new(Vec::new()).unwrap_err(), KeyError::Empty);
    assert_eq!(
        RedactionKey::new(b"0123456789abcde".to_vec()).unwrap_err(),
        KeyError::TooShort
    );
    assert!(RedactionKey::new(b"0123456789abcdef".to_vec()).is_ok());
    assert!(
        RedactionKey::from_optional(None)
            .expect("unset is ordinal")
            .is_none()
    );
    assert_eq!(
        RedactionKey::from_optional(Some(b"")).unwrap_err(),
        KeyError::Empty
    );
}

#[test]
fn a_set_but_bad_tool_key_never_falls_back() {
    assert_eq!(FALLBACK_ENV, "CMDRVL_REDACTION_KEY");
    let good: &[u8] = b"0123456789abcdef";
    // Planted negative: a bad tool key with a perfectly good fallback is still an error.
    assert_eq!(
        select_key(Some(b""), Some(good)).unwrap_err(),
        KeyError::Empty
    );
    assert_eq!(
        select_key(Some(b"short"), Some(good)).unwrap_err(),
        KeyError::TooShort
    );
    // Unset tool variable: the fallback is used, and a bad fallback is also an error.
    let chosen = select_key(None, Some(good))
        .expect("fallback")
        .expect("keyed");
    assert_eq!(
        chosen.marker_raw(b"open"),
        key("0123456789abcdef").marker_raw(b"open")
    );
    assert_eq!(
        select_key(None, Some(b"x")).unwrap_err(),
        KeyError::TooShort
    );
    assert!(select_key(None, None).expect("both unset").is_none());
    // The tool key wins over a different fallback.
    let tool = select_key(Some(b"fedcba9876543210"), Some(good))
        .expect("tool key")
        .expect("keyed");
    assert_eq!(
        tool.marker_raw(b"open"),
        key("fedcba9876543210").marker_raw(b"open")
    );
}

#[test]
fn ordinal_refs_follow_first_appearance_per_namespace_and_hash_nothing() {
    let mut marker = Marker::ordinal();
    assert!(!marker.is_keyed());
    // Marked in data order: "zeta" first, although "alpha" sorts first.
    assert_eq!(marker.mark(Namespace::COLUMN, b"zeta"), "redacted:ref:c1");
    assert_eq!(marker.mark(Namespace::COLUMN, b"alpha"), "redacted:ref:c2");
    assert_eq!(marker.mark(Namespace::COLUMN, b"zeta"), "redacted:ref:c1");
    assert_eq!(marker.mark(Namespace::VALUE, b"zeta"), "redacted:ref:v1");
    assert_eq!(marker.mark(Namespace::ROW, b"zeta"), "redacted:ref:k1");
    // ROW and METADATA_KEY share the letter k but not the numbering.
    assert_eq!(
        marker.mark(Namespace::METADATA_KEY, b"other"),
        "redacted:ref:k1"
    );
    assert_eq!(marker.ordinal_of(Namespace::COLUMN, b"alpha"), 2);
    assert_eq!(marker.ordinal_of(Namespace::COLUMN, b"new"), 3);
    let mut again = Marker::ordinal();
    assert_eq!(again.mark(Namespace::COLUMN, b"zeta"), "redacted:ref:c1");
}

#[test]
fn debug_output_never_shows_the_key() {
    let key = key("PLANTED-KEY-0123456789");
    assert!(!format!("{key:?}").contains("PLANTED"));
    assert!(!format!("{:?}", Marker::keyed(&key, Scheme::Raw)).contains("PLANTED"));
}
