//! `lock.v0` conformance. COPY of spine-rules `src/lockfile.rs` (conformance part) and
//! `tests/lockfile.rs` at commit 2d1e23ad7eecaa53ff7441f6331ee6bdd6cff53d, with the fixtures in
//! `fixtures/lock_v0/` (real `vacuum | hashbytes | lock` output, copied from the same commit).
//! Retargeted at cmdrvl-core. There are 10 cases. If spine-rules' cases change, re-copy them.

use std::panic::{AssertUnwindSafe, catch_unwind};

use cmdrvl_core::hash::{Algorithm, hash_bytes};
use cmdrvl_core::lockfile::{LockRefusal, MemberVerdict, candidates, parse, verify_member};

const LOANS_CSV: &str = include_str!("fixtures/lock_v0/loans.csv");
const REAL_SHA256_LOCK: &str = include_str!("fixtures/lock_v0/sha256.lock.json");
const REAL_BLAKE3_LOCK: &str = include_str!("fixtures/lock_v0/blake3.lock.json");
const LOANS: &[u8] = LOANS_CSV.as_bytes();

// ── copied case list ────────────────────────────────────────────────────

/// What a tool's `--lock` check must conclude for a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Verified,
    Drift,
    NotLocked,
    /// The lock itself is unusable (unknown algorithm, malformed, unknown version).
    Refused,
}

#[derive(Debug, Clone)]
struct ConformanceCase {
    name: String,
    lock_json: String,
    /// Path of the input as the tool sees it.
    input_path: &'static str,
    input_bytes: Vec<u8>,
    expect: Expect,
}

/// The cases every `--lock` implementation must agree on: pass, drift, ambiguous basename
/// for both algorithms, plus not-locked, unknown algorithm, malformed, and unknown version.
fn conformance_cases() -> Vec<ConformanceCase> {
    let good = LOANS_CSV.as_bytes().to_vec();
    let mut tampered = good.clone();
    let last = tampered.len() - 2;
    tampered[last] = if tampered[last] == b'9' { b'8' } else { b'9' };

    let mut cases = Vec::new();
    for (algorithm, lock) in [
        (Algorithm::Sha256, REAL_SHA256_LOCK),
        (Algorithm::Blake3, REAL_BLAKE3_LOCK),
    ] {
        let prefix = algorithm.prefix();
        let hash = hash_bytes(algorithm, &good);
        let two_members = format!(
            r#"{{"version":"lock.v0","members":[{{"path":"a/loans.csv","bytes_hash":"{hash}"}},{{"path":"b/loans.csv","bytes_hash":"{hash}"}}]}}"#
        );
        cases.push(ConformanceCase {
            name: format!("{prefix} real lock: matching bytes verify"),
            lock_json: lock.to_owned(),
            input_path: "loans.csv",
            input_bytes: good.clone(),
            expect: Expect::Verified,
        });
        cases.push(ConformanceCase {
            name: format!("{prefix} real lock: a changed byte is drift"),
            lock_json: lock.to_owned(),
            input_path: "loans.csv",
            input_bytes: tampered.clone(),
            expect: Expect::Drift,
        });
        cases.push(ConformanceCase {
            name: format!("{prefix}: two members with one basename are not locked"),
            lock_json: two_members,
            input_path: "loans.csv",
            input_bytes: good.clone(),
            expect: Expect::NotLocked,
        });
    }
    cases.push(ConformanceCase {
        name: "real lock, input not in it: not locked".to_owned(),
        lock_json: REAL_BLAKE3_LOCK.to_owned(),
        input_path: "other.csv",
        input_bytes: good.clone(),
        expect: Expect::NotLocked,
    });
    cases.push(ConformanceCase {
        name: "unknown algorithm prefix is refused, not guessed".to_owned(),
        lock_json: REAL_SHA256_LOCK.replace("sha256:973ef89c", "md5:973ef89c"),
        input_path: "loans.csv",
        input_bytes: good.clone(),
        expect: Expect::Refused,
    });
    cases.push(ConformanceCase {
        name: "member without bytes_hash is refused".to_owned(),
        lock_json: r#"{"version":"lock.v0","members":[{"path":"loans.csv"}]}"#.to_owned(),
        input_path: "loans.csv",
        input_bytes: good.clone(),
        expect: Expect::Refused,
    });
    cases.push(ConformanceCase {
        name: "unknown lock version is refused".to_owned(),
        lock_json: r#"{"version":"lock.v9","members":[]}"#.to_owned(),
        input_path: "loans.csv",
        input_bytes: good,
        expect: Expect::Refused,
    });
    cases
}

/// Run `check` over every conformance case and assert it reaches the expected conclusion.
/// `check(lock_json, input_path, input_bytes)` is the tool's own `--lock` logic reduced to
/// an [`Expect`]. Panics naming every case that disagrees.
fn run_conformance(check: impl Fn(&str, &str, &[u8]) -> Expect) {
    let failures: Vec<String> = conformance_cases()
        .into_iter()
        .filter_map(|case| {
            let got = check(&case.lock_json, case.input_path, &case.input_bytes);
            (got != case.expect)
                .then(|| format!("{}: expected {:?}, got {got:?}", case.name, case.expect))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "lock.v0 conformance failures:\n  - {}",
        failures.join("\n  - ")
    );
}

/// The reference implementation as a `check` function, so the fixtures prove themselves.
fn reference_check(lock_json: &str, input_path: &str, bytes: &[u8]) -> Expect {
    match parse(lock_json).and_then(|lock| verify_member(&lock, input_path, bytes)) {
        Ok(MemberVerdict::Verified { .. }) => Expect::Verified,
        Ok(MemberVerdict::Drift { .. }) => Expect::Drift,
        Ok(MemberVerdict::NotLocked) => Expect::NotLocked,
        Err(_) => Expect::Refused,
    }
}

// ── copied tests ────────────────────────────────────────────────────────

#[test]
fn the_reference_implementation_passes_every_case() {
    run_conformance(reference_check);
}

#[test]
fn both_algorithms_verify_with_the_members_own_algorithm() {
    for (lock, expected) in [
        (REAL_SHA256_LOCK, Algorithm::Sha256),
        (REAL_BLAKE3_LOCK, Algorithm::Blake3),
    ] {
        let lock = parse(lock).expect("real lock parses");
        let verdict = verify_member(&lock, "loans.csv", LOANS).expect("usable lock");
        assert!(
            matches!(&verdict, MemberVerdict::Verified { algorithm, .. } if *algorithm == expected),
            "expected Verified with {expected:?}, got {verdict:?}"
        );
    }
}

#[test]
fn drift_reports_the_locks_prefix_on_both_sides() {
    let mut tampered = LOANS.to_vec();
    tampered[0] ^= 1;
    for (lock, prefix) in [(REAL_SHA256_LOCK, "sha256:"), (REAL_BLAKE3_LOCK, "blake3:")] {
        let lock = parse(lock).expect("real lock parses");
        let verdict = verify_member(&lock, "loans.csv", &tampered).expect("usable lock");
        let drifted = matches!(
            &verdict,
            MemberVerdict::Drift { expected, observed, .. }
                if expected.starts_with(prefix) && observed.starts_with(prefix) && expected != observed
        );
        assert!(
            drifted,
            "expected Drift with {prefix} on both sides, got {verdict:?}"
        );
    }
}

#[test]
fn refusals_are_typed() {
    assert!(matches!(parse("{"), Err(LockRefusal::Malformed(_))));
    assert!(matches!(
        parse(r#"{"version":"lock.v1","members":[]}"#),
        Err(LockRefusal::UnsupportedVersion(_))
    ));
    let lock =
        parse(r#"{"version":"lock.v0","members":[{"path":"loans.csv","bytes_hash":"md5:00"}]}"#)
            .expect("parses");
    assert!(matches!(
        verify_member(&lock, "loans.csv", LOANS),
        Err(LockRefusal::UnknownAlgorithm { .. })
    ));
}

/// The drift this bead exists for: a verifier that hardcodes sha256 (like benchmark's did).
fn sha256_only(lock_json: &str, input_path: &str, bytes: &[u8]) -> Expect {
    let Ok(lock) = parse(lock_json) else {
        return Expect::Refused;
    };
    let matches = candidates(&lock, input_path);
    let Some(member) = matches.first() else {
        return Expect::NotLocked;
    };
    if member.bytes_hash == hash_bytes(Algorithm::Sha256, bytes) {
        Expect::Verified
    } else {
        Expect::Drift
    }
}

/// A verifier that picks the first basename match even when it is ambiguous.
fn guesses_ambiguous_basenames(lock_json: &str, input_path: &str, bytes: &[u8]) -> Expect {
    let Ok(lock) = parse(lock_json) else {
        return Expect::Refused;
    };
    let name = input_path.rsplit('/').next().unwrap_or(input_path);
    let Some(member) = lock.members.iter().find(|m| m.path.ends_with(name)) else {
        return Expect::NotLocked;
    };
    match Algorithm::of(&member.bytes_hash) {
        None => Expect::Refused,
        Some(alg) if hash_bytes(alg, bytes) == member.bytes_hash => Expect::Verified,
        Some(_) => Expect::Drift,
    }
}

fn conformance_failure(check: fn(&str, &str, &[u8]) -> Expect) -> String {
    let payload = catch_unwind(AssertUnwindSafe(|| run_conformance(check)))
        .expect_err("a wrong implementation must fail conformance");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default()
}

#[test]
fn a_sha256_only_verifier_is_caught_on_the_blake3_cases() {
    let message = conformance_failure(sha256_only);
    assert!(
        message.contains("blake3 real lock: matching bytes verify"),
        "{message}"
    );
    assert!(
        !message.contains("sha256 real lock: matching bytes verify"),
        "the sha256 case should have passed: {message}"
    );
    assert!(message.contains("unknown algorithm"), "{message}");
}

#[test]
fn a_verifier_that_guesses_ambiguous_basenames_is_caught() {
    let message = conformance_failure(guesses_ambiguous_basenames);
    assert!(
        message.contains("two members with one basename"),
        "{message}"
    );
}

#[test]
fn the_case_list_covers_pass_drift_and_unknown_for_both_algorithms() {
    let names: Vec<String> = conformance_cases().into_iter().map(|c| c.name).collect();
    for needed in [
        "sha256 real lock: matching bytes verify",
        "sha256 real lock: a changed byte is drift",
        "blake3 real lock: matching bytes verify",
        "blake3 real lock: a changed byte is drift",
        "unknown algorithm prefix is refused, not guessed",
    ] {
        assert!(
            names.iter().any(|name| name == needed),
            "missing case: {needed}"
        );
    }
}

#[test]
fn there_are_exactly_ten_copied_cases_with_unique_names() {
    let names: std::collections::BTreeSet<String> =
        conformance_cases().into_iter().map(|c| c.name).collect();
    assert_eq!(conformance_cases().len(), 10);
    assert_eq!(names.len(), 10);
}
