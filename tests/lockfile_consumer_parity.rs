//! `core::lockfile` against the released `--lock` consumers.
//!
//! `fixtures/lock_consumers/released.json` holds verdicts OBSERVED from released programs (its
//! `released` member names the versions), not computed by this crate. Each case is a set of
//! `lock.v0` documents and an input path. A member is `[path, kind]`: `good` is the input's
//! sha256, `bad` a different well-formed digest, `md5` an unsupported algorithm and `short` a
//! malformed sha256. `verify-run` and `verify-ground` are `verify run` and `verify ground`.
//!
//! The rule: core never verifies what any released consumer refused. Set
//! `LOCK_PARITY_FIXTURE=<file>` to check another recording of the same shape instead.

use cmdrvl_core::hash::{Algorithm, hash_bytes};
use cmdrvl_core::lockfile::{
    LockRefusal, LockV0, MemberVerdict, candidates, parse, verify_member, verify_member_in_locks,
};
use serde_json::{Value, json};

const RELEASED: &str = include_str!("fixtures/lock_consumers/released.json");
const INPUT: &[u8] = b"loan_id,balance\n1,2\n";
const CONSUMERS: [&str; 5] = ["shape", "rvl", "benchmark", "verify-run", "verify-ground"];

struct Case {
    name: String,
    input: String,
    locks: Vec<LockV0>,
    observed: Vec<String>,
    refused_by: Vec<&'static str>,
}

impl Case {
    fn verdict(&self) -> Result<MemberVerdict, LockRefusal> {
        let locks: Vec<&LockV0> = self.locks.iter().collect();
        verify_member_in_locks(&locks, &self.input, INPUT)
    }

    fn core_verifies(&self) -> bool {
        matches!(self.verdict(), Ok(MemberVerdict::Verified { .. }))
    }
}

fn cases() -> Vec<Case> {
    let other = std::env::var("LOCK_PARITY_FIXTURE").ok();
    cases_from(&match other {
        Some(path) => std::fs::read_to_string(path).expect("LOCK_PARITY_FIXTURE reads"),
        None => RELEASED.to_owned(),
    })
}

fn cases_from(record: &str) -> Vec<Case> {
    let record: Value = serde_json::from_str(record).expect("fixture is JSON");
    record["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| Case {
            name: case["name"].as_str().expect("name").to_owned(),
            input: case["input"].as_str().expect("input").to_owned(),
            locks: case["locks"]
                .as_array()
                .expect("locks")
                .iter()
                .map(lock_from)
                .collect(),
            observed: CONSUMERS
                .iter()
                .map(|consumer| {
                    case["observed"][consumer]
                        .as_str()
                        .expect("verdict")
                        .to_owned()
                })
                .collect(),
            refused_by: CONSUMERS
                .into_iter()
                .filter(|consumer| {
                    let observed = case["observed"][consumer].as_str().expect("verdict");
                    observed != "VERIFIED"
                })
                .collect(),
        })
        .collect()
}

fn lock_from(members: &Value) -> LockV0 {
    let members: Vec<Value> = members
        .as_array()
        .expect("members")
        .iter()
        .map(|member| {
            let bytes_hash = match member[1].as_str().expect("kind") {
                "good" => hash_bytes(Algorithm::Sha256, INPUT),
                "bad" => format!("sha256:{}", "0".repeat(64)),
                "md5" => format!("md5:{}", "0".repeat(32)),
                "short" => "sha256:00".to_owned(),
                other => panic!("unknown kind {other}"),
            };
            json!({"path": member[0], "bytes_hash": bytes_hash})
        })
        .collect();
    let document = json!({"version": "lock.v0", "members": members});
    parse(&document.to_string()).expect("fixture lock parses")
}

#[test]
fn the_fixture_has_cases_the_consumers_accept_and_refuse() {
    let cases = cases_from(RELEASED);
    assert_eq!(cases.len(), 37);
    assert!(cases.iter().any(|case| case.refused_by.is_empty()));
    assert!(
        cases
            .iter()
            .any(|case| case.refused_by.len() == CONSUMERS.len())
    );
}

#[test]
fn core_never_verifies_what_a_released_consumer_refused() {
    let cases = cases();
    let accepted = cases.iter().filter(|case| case.refused_by.is_empty());
    let both = accepted.clone().filter(|case| case.core_verifies()).count();
    // Shown with --nocapture: the check below means nothing if core verifies nothing.
    println!(
        "{} cases; every consumer verified {}, core verified {both} of those",
        cases.len(),
        accepted.count()
    );
    assert!(both > 0, "core verified none of the accepted cases");
    let looser: Vec<String> = cases
        .iter()
        .filter(|case| !case.refused_by.is_empty() && case.core_verifies())
        .map(|case| format!("{} (refused by {})", case.name, case.refused_by.join(", ")))
        .collect();
    assert!(
        looser.is_empty(),
        "core verified {} refused cases:\n  - {}",
        looser.len(),
        looser.join("\n  - ")
    );
}

/// The cost of the rule, listed in full so that refusing more is a visible change.
#[test]
fn core_refuses_only_these_cases_that_every_consumer_accepted() {
    let stricter: Vec<String> = cases_from(RELEASED)
        .into_iter()
        .filter(|case| case.refused_by.is_empty() && !case.core_verifies())
        .map(|case| case.name)
        .collect();
    assert_eq!(
        stricter,
        [
            // The earlier rule refused these three, and the change only tightens it.
            "trailing slash member alone",
            "member ./old.csv beside d/old.csv",
            "member ./old.csv good, input ./old.csv, old.csv bad",
            // `shape` recognises one lock file passed twice; core sees no files.
            "same lock passed twice",
        ]
    );
}

#[test]
fn where_every_consumer_gave_one_refusal_core_gives_the_same() {
    let mut compared = 0;
    for case in cases_from(RELEASED) {
        let first = case.observed[0].as_str();
        if !case.observed.iter().all(|seen| seen == first) {
            continue;
        }
        let same = match (first, case.verdict()) {
            ("E_INPUT_NOT_LOCKED", verdict) => verdict == Ok(MemberVerdict::NotLocked),
            ("E_INPUT_DRIFT", verdict) => matches!(verdict, Ok(MemberVerdict::Drift { .. })),
            ("VERIFIED", _) => continue,
            ("E_IO", verdict) => verdict.is_err(),
            (other, _) => panic!("unexpected shared refusal {other}"),
        };
        assert!(
            same,
            "{}: all said {first}, core {:?}",
            case.name,
            case.verdict()
        );
        compared += 1;
    }
    assert!(compared >= 5, "only {compared} cases compared");
}

/// Calling [`verify_member`] once per lock and accepting any success is looser than `shape`.
#[test]
fn several_locks_must_be_checked_together() {
    let case = cases_from(RELEASED)
        .into_iter()
        .find(|case| case.name == "same member path in two locks")
        .expect("case");
    assert!(case.refused_by.contains(&"shape"));
    assert!(case.locks.iter().all(|lock| matches!(
        verify_member(lock, &case.input, INPUT),
        Ok(MemberVerdict::Verified { .. })
    )));
    assert_eq!(case.verdict(), Ok(MemberVerdict::NotLocked));
}

/// NOT observed: no Windows build was run. On Windows `Path::file_name` also splits on `\`, so
/// the second member below is another `old.csv`; every Unix rule sees only the first.
#[test]
fn the_windows_rule_counts_a_name_the_other_rules_cannot_see() {
    let good = hash_bytes(Algorithm::Sha256, INPUT);
    let lock = |second: &str| {
        let document = json!({"version": "lock.v0", "members": [
            {"path": "d/old.csv", "bytes_hash": good}, {"path": second, "bytes_hash": good}]});
        parse(&document.to_string()).expect("lock parses")
    };
    assert_eq!(
        verify_member(&lock("e\\old.csv\\."), "old.csv", INPUT),
        Ok(MemberVerdict::NotLocked)
    );
    assert!(candidates(&lock("e\\old.csv\\."), "old.csv").is_empty());
    // Control: with an unrelated second member the same call verifies.
    assert!(matches!(
        verify_member(&lock("e\\other.csv\\."), "old.csv", INPUT),
        Ok(MemberVerdict::Verified { .. })
    ));
}
