//! R1 lock matching tests. The reference functions in this file intentionally do not call
//! `cmdrvl_core::lock_matching`; the exhaustive test is a differential check against the prose
//! rule from cmd-zjr's approved design.

use cmdrvl_core::hash::{Algorithm, hash_bytes};
use cmdrvl_core::lock_matching::{Basis, Member, SelectError, Verdict, select};

const MATCH: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const MD5: &str = "md5:00000000000000000000000000000000";
const SHORT: &str = "sha256:00";
const UPPER: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PATHS: [&str; 6] = [
    "loans.csv",
    "./loans.csv",
    "d/loans.csv",
    "e/loans.csv",
    "e\\loans.csv",
    "other.csv",
];
const NAMES: [&str; 4] = ["loans.csv", "./loans.csv", "d/loans.csv", "./d/loans.csv"];
const DIGESTS: [&str; 2] = [MATCH, OTHER];

fn member(lock: usize, path: &'static str, digest: &'static str) -> Member<'static> {
    Member { lock, path, digest }
}

fn normalized(path: &str) -> &str {
    let mut path = path;
    while let Some(rest) = path.strip_prefix("./") {
        path = rest;
    }
    path
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

fn usable(digest: &str) -> bool {
    let Some(algorithm) = Algorithm::of(digest) else {
        return false;
    };
    let hex = &digest[algorithm.prefix().len() + 1..];
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug)]
enum IndependentSelection {
    NotListed,
    SeveralPaths(Vec<Member<'static>>),
    UnusableDigest(Member<'static>),
    Selected {
        basis: Basis,
        candidates: Vec<Member<'static>>,
    },
}

fn independent_select(input: &str, members: &[Member<'static>]) -> IndependentSelection {
    let input = normalized(input);
    let normalized_members: Vec<Member<'static>> = members
        .iter()
        .map(|candidate| Member {
            lock: candidate.lock,
            path: normalized(candidate.path),
            digest: candidate.digest,
        })
        .collect();
    let exact: Vec<Member<'static>> = normalized_members
        .iter()
        .filter(|candidate| candidate.path == input)
        .cloned()
        .collect();
    let (basis, candidates) = if exact.is_empty() {
        let name = basename(input);
        if name.is_empty() {
            return IndependentSelection::NotListed;
        }
        let by_name: Vec<Member<'static>> = normalized_members
            .iter()
            .filter(|candidate| basename(candidate.path) == name)
            .cloned()
            .collect();
        if by_name.is_empty() {
            return IndependentSelection::NotListed;
        }
        let mut paths: Vec<&str> = Vec::new();
        for candidate in &by_name {
            if !paths.contains(&candidate.path) {
                paths.push(candidate.path);
            }
        }
        if paths.len() != 1 {
            return IndependentSelection::SeveralPaths(by_name);
        }
        (Basis::FileName, by_name)
    } else {
        (Basis::ExactPath, exact)
    };
    if let Some(candidate) = candidates
        .iter()
        .find(|candidate| !usable(candidate.digest))
    {
        return IndependentSelection::UnusableDigest(candidate.clone());
    }
    IndependentSelection::Selected { basis, candidates }
}

#[derive(Debug)]
enum IndependentVerdict {
    Verified {
        locks: Vec<usize>,
        matched: Vec<Member<'static>>,
    },
    Drift {
        matching_locks: Vec<usize>,
        matched: Vec<Member<'static>>,
        differing: Vec<Member<'static>>,
    },
}

fn independent_judge(
    candidates: &[Member<'static>],
    observed: &[(Algorithm, &str)],
) -> Option<IndependentVerdict> {
    let mut matched = Vec::new();
    let mut differing = Vec::new();
    for candidate in candidates {
        let algorithm = Algorithm::of(candidate.digest).expect("independent selection validated");
        let (_, actual) = observed.iter().find(|(kind, _)| *kind == algorithm)?;
        if *actual == candidate.digest {
            matched.push(candidate.clone());
        } else {
            differing.push(candidate.clone());
        }
    }
    if differing.is_empty() {
        Some(IndependentVerdict::Verified {
            locks: matched.iter().map(|candidate| candidate.lock).collect(),
            matched,
        })
    } else {
        Some(IndependentVerdict::Drift {
            matching_locks: matched.iter().map(|candidate| candidate.lock).collect(),
            matched,
            differing,
        })
    }
}

fn assert_selection_matches(input: &str, members: Vec<Member<'static>>) {
    let expected = independent_select(input, &members);
    let actual = select(input, members);
    match (expected, actual) {
        (IndependentSelection::NotListed, Err(SelectError::NotListed)) => {}
        (IndependentSelection::SeveralPaths(expected), Err(SelectError::SeveralPaths(actual))) => {
            assert_eq!(actual, expected, "several-path candidates")
        }
        (
            IndependentSelection::UnusableDigest(expected),
            Err(SelectError::UnusableDigest(actual)),
        ) => assert_eq!(actual, expected, "unusable candidate"),
        (IndependentSelection::Selected { basis, candidates }, Ok(actual)) => {
            assert_eq!(actual.basis, basis);
            assert_eq!(actual.candidates, candidates);
            let expected_verdict = independent_judge(&candidates, &[(Algorithm::Sha256, MATCH)])
                .expect("the exhaustive observer supplies sha256");
            let actual_verdict = actual.judge(&[(Algorithm::Sha256, MATCH)]).unwrap();
            match (expected_verdict, actual_verdict) {
                (
                    IndependentVerdict::Verified { locks, matched },
                    Verdict::Verified {
                        locks: actual_locks,
                        matched: actual_matched,
                    },
                ) => {
                    assert_eq!(actual_locks, locks);
                    assert_eq!(actual_matched, matched);
                }
                (
                    IndependentVerdict::Drift {
                        matching_locks,
                        matched,
                        differing,
                    },
                    Verdict::Drift {
                        matching_locks: actual_matching_locks,
                        matched: actual_matched,
                        differing: actual_differing,
                    },
                ) => {
                    assert_eq!(actual_matching_locks, matching_locks);
                    assert_eq!(actual_matched, matched);
                    assert_eq!(actual_differing, differing);
                }
                (expected, actual) => {
                    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                }
            }
        }
        (expected, actual) => {
            assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        }
    }
}

#[test]
fn edge_cases_one_through_thirteen_are_pinned() {
    // 1. A sha256 match beside a non-matching blake3 candidate is now Drift.
    assert_selection_matches(
        "loans.csv",
        vec![member(0, "loans.csv", MATCH), member(1, "loans.csv", OTHER)],
    );
    // 2-3. Every candidate is validated, regardless of lock order.
    assert!(matches!(
        select(
            "loans.csv",
            vec![member(0, "loans.csv", MATCH), member(0, "loans.csv", MD5)]
        ),
        Err(SelectError::UnusableDigest(Member {
            path: "loans.csv",
            ..
        }))
    ));
    assert!(matches!(
        select(
            "loans.csv",
            vec![member(0, "loans.csv", MD5), member(0, "loans.csv", MATCH)]
        ),
        Err(SelectError::UnusableDigest(Member {
            path: "loans.csv",
            ..
        }))
    ));
    assert!(matches!(
        select("loans.csv", vec![member(0, "loans.csv", SHORT)]),
        Err(SelectError::UnusableDigest(Member {
            path: "loans.csv",
            ..
        }))
    ));
    // 4-6. Whitespace, trailing separators and a dot basename are not normalized.
    for (input, path) in [
        ("loans.csv", " loans.csv"),
        ("loans.csv", "loans.csv/"),
        ("d", "d/."),
    ] {
        assert!(matches!(
            select(input, vec![member(0, path, MATCH)]),
            Err(SelectError::NotListed)
        ));
    }
    // 7. All leading ./ components are dropped before exact matching.
    assert_selection_matches(
        "loans.csv",
        vec![
            member(0, "././loans.csv", MATCH),
            member(0, "a/loans.csv", OTHER),
        ],
    );
    // 8. Case is significant.
    assert!(matches!(
        select("loans.csv", vec![member(0, "Loans.csv", MATCH)]),
        Err(SelectError::NotListed)
    ));
    // 9. Uppercase hex is usable but is a different digest string, so it drifts.
    assert_selection_matches("loans.csv", vec![member(0, "loans.csv", UPPER)]);
    // 10-11. Backslash is an ordinary character in R1.
    assert!(matches!(
        select("e\\loans.csv", vec![member(0, "loans.csv", MATCH)]),
        Err(SelectError::NotListed)
    ));
    assert!(matches!(
        select(
            "e\\loans.csv",
            vec![
                member(0, "e/loans.csv", MATCH),
                member(0, "loans.csv", OTHER)
            ]
        ),
        Err(SelectError::NotListed)
    ));
    // 12. A normal slash basename still finds a member with a different parent.
    assert_selection_matches(
        "x/loans.csv",
        vec![
            member(0, "a\\loans.csv", OTHER),
            member(0, "loans.csv", MATCH),
        ],
    );
    // 13. The same lock position may appear twice when the caller passed it twice.
    let selected = select(
        "loans.csv",
        vec![
            member(0, "d/loans.csv", MATCH),
            member(1, "d/loans.csv", MATCH),
        ],
    )
    .unwrap();
    assert_eq!(selected.basis, Basis::FileName);
    assert_eq!(selected.algorithms(), vec![Algorithm::Sha256]);
    assert_eq!(
        selected.judge(&[(Algorithm::Sha256, MATCH)]),
        Ok(Verdict::Verified {
            locks: vec![0, 1],
            matched: vec![
                member(0, "d/loans.csv", MATCH),
                member(1, "d/loans.csv", MATCH)
            ],
        })
    );
}

#[test]
fn changed_accept_and_refuse_classes_have_concrete_examples() {
    // Newly refused: exact-path disagreement across locks, exact disagreement in one lock,
    // and file-name disagreement in one lock all become Drift.
    for members in [
        vec![member(0, "loans.csv", MATCH), member(1, "loans.csv", OTHER)],
        vec![
            member(0, "loans.csv", MATCH),
            member(0, "./loans.csv", OTHER),
        ],
        vec![
            member(0, "d/loans.csv", MATCH),
            member(0, "d/loans.csv", OTHER),
        ],
    ] {
        let selection = select("loans.csv", members).unwrap();
        assert!(matches!(
            selection.judge(&[(Algorithm::Sha256, MATCH)]),
            Ok(Verdict::Drift { .. })
        ));
    }
    // Newly accepted: equivalent leading ./ spellings and one same-digest path in two locks.
    for members in [
        vec![
            member(0, "./loans.csv", MATCH),
            member(0, "d/loans.csv", MATCH),
        ],
        vec![
            member(0, "./loans.csv", MATCH),
            member(1, "./loans.csv", MATCH),
        ],
    ] {
        let selection = select("loans.csv", members).unwrap();
        assert!(matches!(
            selection.judge(&[(Algorithm::Sha256, MATCH)]),
            Ok(Verdict::Verified { .. })
        ));
    }
}

#[test]
fn either_of_two_locks_with_different_digests_is_drift() {
    let selection = select(
        "loans.csv",
        vec![member(0, "loans.csv", MATCH), member(1, "loans.csv", OTHER)],
    )
    .unwrap();
    assert_eq!(
        selection.judge(&[(Algorithm::Sha256, MATCH)]),
        Ok(Verdict::Drift {
            matching_locks: vec![0],
            matched: vec![member(0, "loans.csv", MATCH)],
            differing: vec![member(1, "loans.csv", OTHER)],
        })
    );
}

#[test]
fn two_period_parent_folder_passes_right_and_drifts_when_exchanged() {
    let members = vec![
        member(0, "dec/loans.csv", MATCH),
        member(0, "nov/loans.csv", OTHER),
    ];
    for (path, observed, expected) in [
        ("dec/loans.csv", MATCH, true),
        ("nov/loans.csv", OTHER, true),
    ] {
        let selection = select(path, members.clone()).unwrap();
        assert_eq!(
            selection.judge(&[(Algorithm::Sha256, observed)]).is_ok(),
            expected,
            "right parent-folder layout"
        );
    }
    for (path, observed) in [("dec/loans.csv", OTHER), ("nov/loans.csv", MATCH)] {
        let selection = select(path, members.clone()).unwrap();
        assert!(matches!(
            selection.judge(&[(Algorithm::Sha256, observed)]),
            Ok(Verdict::Drift { .. })
        ));
    }
}

#[test]
fn judge_requires_every_algorithm_selected() {
    let selection = select(
        "loans.csv",
        vec![
            member(0, "loans.csv", MATCH),
            member(
                1,
                "./loans.csv",
                "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        selection.algorithms(),
        vec![Algorithm::Sha256, Algorithm::Blake3]
    );
    assert_eq!(
        selection.judge(&[(Algorithm::Sha256, MATCH)]),
        Err(cmdrvl_core::lock_matching::MissingDigest {
            algorithm: Algorithm::Blake3,
        })
    );
}

fn generated_members(layout: usize) -> Vec<Member<'static>> {
    if layout < 12 {
        let path = PATHS[layout / 2];
        let digest = DIGESTS[layout % 2];
        return vec![member(0, path, digest)];
    }
    let layout = layout - 12;
    let two_locks = layout >= 144;
    let pair = layout % 144;
    let first = pair / 12;
    let second = pair % 12;
    let (first_path, first_digest) = (PATHS[first / 2], DIGESTS[first % 2]);
    let (second_path, second_digest) = (PATHS[second / 2], DIGESTS[second % 2]);
    if !two_locks {
        vec![
            member(0, first_path, first_digest),
            member(0, second_path, second_digest),
        ]
    } else {
        vec![
            member(0, first_path, first_digest),
            member(1, second_path, second_digest),
        ]
    }
}

#[test]
fn exhaustive_four_names_by_three_hundred_layouts_matches_independent_rule() {
    let mut total = 0;
    let mut verified = 0;
    let mut drift = 0;
    let mut not_listed = 0;
    let mut several_paths = 0;
    for input in NAMES {
        for layout in 0..300 {
            let members = generated_members(layout);
            match independent_select(input, &members) {
                IndependentSelection::Selected { .. } => {
                    let actual = select(input, members).expect("independent selection selected");
                    match actual.judge(&[(Algorithm::Sha256, MATCH)]) {
                        Ok(Verdict::Verified { .. }) => verified += 1,
                        Ok(Verdict::Drift { .. }) => drift += 1,
                        Err(error) => assert_ne!(
                            error.algorithm,
                            Algorithm::Sha256,
                            "unexpected missing digest"
                        ),
                    }
                    assert_selection_matches(input, generated_members(layout));
                }
                IndependentSelection::NotListed => {
                    not_listed += 1;
                    assert_selection_matches(input, members);
                }
                IndependentSelection::SeveralPaths(_) => {
                    several_paths += 1;
                    assert_selection_matches(input, members);
                }
                IndependentSelection::UnusableDigest(_) => {
                    assert_selection_matches(input, members);
                }
            }
            total += 1;
        }
    }
    assert_eq!(total, 1_200);
    assert_eq!(verified + drift + not_listed + several_paths, total);
    println!(
        "R1 generated verdicts: verified={verified}, drift={drift}, not_listed={not_listed}, several_paths={several_paths}"
    );
}

#[test]
fn input_digest_can_be_computed_without_the_matching_module_reading_bytes() {
    let bytes = b"loan_id,balance\n1,2\n";
    let digest = hash_bytes(Algorithm::Sha256, bytes);
    let selection = select("loans.csv", vec![member(0, "loans.csv", MATCH)]).unwrap();
    assert!(matches!(
        selection.judge(&[(Algorithm::Sha256, &digest)]),
        Ok(Verdict::Drift { .. })
    ));
}
