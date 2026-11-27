//! Pure R1 matching of one input name against lock members.
//!
//! This module deliberately receives names and recorded digests only. It does not read files,
//! hash bytes, inspect the environment or choose a clock. Callers hash their input once for each
//! algorithm returned by [`Selection::algorithms`] and pass those strings to [`Selection::judge`].
//!
//! R1 is intentionally narrower than the historical per-tool rules: every leading `./` is
//! dropped from the typed name and member paths; no other trimming or path cleanup happens;
//! `\\` is an ordinary character; exact normalized paths win, otherwise a non-empty `/` basename
//! must identify one normalized member path; every candidate digest must be usable; and every
//! candidate digest must match the caller's observed digest for its algorithm.

use crate::hash::{Algorithm, HEX_DIGITS};

/// A lock member at its position among the caller's lock arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member<'a> {
    pub lock: usize,
    pub path: &'a str,
    pub digest: &'a str,
}

/// Whether selection used an exact normalized path or a unique file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    ExactPath,
    FileName,
}

/// The non-empty candidate set selected by R1, in lock then member order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection<'a> {
    pub basis: Basis,
    pub candidates: Vec<Member<'a>>,
}

/// Why no usable selection could be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError<'a> {
    NotListed,
    SeveralPaths(Vec<Member<'a>>),
    UnusableDigest(Member<'a>),
}

/// The observed digest for a required algorithm was not supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingDigest {
    pub algorithm: Algorithm,
}

/// A selected input either agrees with every candidate or reports both sides of drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<'a> {
    Verified {
        locks: Vec<usize>,
        matched: Vec<Member<'a>>,
    },
    Drift {
        matching_locks: Vec<usize>,
        matched: Vec<Member<'a>>,
        differing: Vec<Member<'a>>,
    },
}

/// Select the R1 candidates for `input_name`.
pub fn select<'a>(
    input_name: &str,
    members: impl IntoIterator<Item = Member<'a>>,
) -> Result<Selection<'a>, SelectError<'a>> {
    let input_name = normalize(input_name);
    let members: Vec<Member<'a>> = members
        .into_iter()
        .map(|member| Member {
            lock: member.lock,
            path: normalize(member.path),
            digest: member.digest,
        })
        .collect();

    let exact: Vec<Member<'a>> = members
        .iter()
        .filter(|member| member.path == input_name)
        .cloned()
        .collect();
    let (basis, candidates) = if exact.is_empty() {
        let name = basename(input_name);
        if name.is_empty() {
            return Err(SelectError::NotListed);
        }
        let by_name: Vec<Member<'a>> = members
            .iter()
            .filter(|member| basename(member.path) == name)
            .cloned()
            .collect();
        if by_name.is_empty() {
            return Err(SelectError::NotListed);
        }
        let mut paths: Vec<&str> = Vec::new();
        for member in &by_name {
            if !paths.contains(&member.path) {
                paths.push(member.path);
            }
        }
        if paths.len() != 1 {
            return Err(SelectError::SeveralPaths(by_name));
        }
        (Basis::FileName, by_name)
    } else {
        (Basis::ExactPath, exact)
    };

    if let Some(member) = candidates
        .iter()
        .find(|member| usable_algorithm(member.digest).is_none())
    {
        return Err(SelectError::UnusableDigest(member.clone()));
    }
    Ok(Selection { basis, candidates })
}

impl<'a> Selection<'a> {
    /// The distinct hash algorithms required to judge this selection, in first-appearance order.
    pub fn algorithms(&self) -> Vec<Algorithm> {
        let mut algorithms = Vec::new();
        for member in &self.candidates {
            if let Some(algorithm) = usable_algorithm(member.digest)
                && !algorithms.contains(&algorithm)
            {
                algorithms.push(algorithm);
            }
        }
        algorithms
    }

    /// Compare every selected member with the caller's observed algorithm/digest pairs.
    pub fn judge(&self, observed: &[(Algorithm, &str)]) -> Result<Verdict<'a>, MissingDigest> {
        let mut matched = Vec::new();
        let mut differing = Vec::new();
        for member in &self.candidates {
            let algorithm = usable_algorithm(member.digest).unwrap_or(Algorithm::Sha256);
            let Some((_, digest)) = observed.iter().find(|(kind, _)| *kind == algorithm) else {
                return Err(MissingDigest { algorithm });
            };
            if *digest == member.digest {
                matched.push(member.clone());
            } else {
                differing.push(member.clone());
            }
        }
        if differing.is_empty() {
            Ok(Verdict::Verified {
                locks: matched.iter().map(|member| member.lock).collect(),
                matched,
            })
        } else {
            Ok(Verdict::Drift {
                matching_locks: matched.iter().map(|member| member.lock).collect(),
                matched,
                differing,
            })
        }
    }
}

fn normalize(path: &str) -> &str {
    let mut path = path;
    while let Some(rest) = path.strip_prefix("./") {
        path = rest;
    }
    path
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

/// R1 accepts known algorithms with exactly 64 hex digits; matching remains byte-for-byte, so
/// uppercase hex is usable but differs from the lowercase digest produced by core hashers.
fn usable_algorithm(digest: &str) -> Option<Algorithm> {
    let algorithm = Algorithm::of(digest)?;
    let hex = &digest[algorithm.prefix().len() + 1..];
    (hex.len() == HEX_DIGITS && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(algorithm)
}
