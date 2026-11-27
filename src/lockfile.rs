//! `lock.v0` verification.
//!
//! - `members[].bytes_hash` is `<algorithm>:<lowercase hex>` of the RAW file bytes;
//! - a member matches an input by exact path, otherwise by a unique basename; an ambiguous
//!   basename matches nothing;
//! - the input is hashed with the MEMBER'S algorithm; different text is drift; no member is "not
//!   locked".
//!
//! # Never looser than a released tool
//!
//! The released tools do not agree on what "exact path" and "basename" mean, and none of their
//! rules is the strictest on every input. [`verify_member`] therefore answers `Verified` only
//! when ALL of these would:
//!
//! 1. `shape` 0.10.1, `rvl` 0.9.2 and `benchmark` 0.4.0 as built for Unix: the input's `\` is
//!    `/` for the exact match only, a basename is what `std::path::Path::file_name` returns, and
//!    each (lock, member path) is a separate basename match, of which only the first listed
//!    entry is checked;
//! 2. the same three as built for Windows, where `\` separates too (taken from the semantics of
//!    `Path::file_name`; those builds have not been run against these cases);
//! 3. `verify` 0.7.6 (`run` and `ground`): both paths are trimmed and lose a leading `./` and
//!    trailing separators, and basenames are ambiguous only if the member PATHS differ;
//! 4. this crate's earlier rule (`spine_rules::lockfile`, commit 2d1e23a), so that nothing it
//!    refused is accepted now.
//!
//! Like `verify ground`, a lock is refused as a whole if ANY member's `bytes_hash` is not
//! `blake3:` or `sha256:` followed by 64 hex digits. So core refuses some inputs that a given
//! tool accepts: moving a tool onto this module can change what that tool accepts.
//! `tests/lockfile_consumer_parity.rs` holds the released verdicts.
//!
//! This crate does not depend on spine-rules (spine-rules may depend on it later).
//! `tests/lockfile_conformance.rs` is a copy of spine-rules' cases, which both still pass.
//!
//! The lock's own `lock_hash` self-hash is checked separately by [`verify_lock_hash`], which
//! reproduces `lock` (`src/lockfile/self_hash.rs`, commit 8c0cdd9).

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::Value;

use crate::hash::{Algorithm, HEX_DIGITS, hash_bytes};
use crate::sorted_compact;

#[derive(Debug, Clone, Deserialize)]
pub struct LockMember {
    pub path: String,
    pub bytes_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LockV0 {
    pub version: String,
    #[serde(default)]
    pub lock_hash: Option<String>,
    pub members: Vec<LockMember>,
}

/// Why a lock file could not be used at all (as opposed to an input failing it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockRefusal {
    /// Not JSON, or not shaped like `lock.v0` (for example a member without `bytes_hash`).
    Malformed(String),
    UnsupportedVersion(String),
    /// A member (matched or not) names an algorithm other than `blake3` or `sha256`.
    UnknownAlgorithm {
        member: String,
        bytes_hash: String,
    },
    /// A member (matched or not) has a known prefix without 64 hex digits after it.
    MalformedDigest {
        member: String,
        bytes_hash: String,
    },
}

/// Result of checking one input against one lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberVerdict {
    Verified {
        member: String,
        algorithm: Algorithm,
    },
    Drift {
        member: String,
        expected: String,
        observed: String,
    },
    NotLocked,
}

pub fn parse(lock_json: &str) -> Result<LockV0, LockRefusal> {
    let lock: LockV0 = serde_json::from_str(lock_json)
        .map_err(|error| LockRefusal::Malformed(error.to_string()))?;
    if lock.version != "lock.v0" {
        return Err(LockRefusal::UnsupportedVersion(lock.version));
    }
    Ok(lock)
}

/// The last component after splitting on both separators (rules 3 and 4).
fn split_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or("")
}

/// `std::path::Path::file_name` for one platform (rules 1 and 2), on any build target: empty and
/// `.` components are skipped and a final `..` has no name. Windows also splits on `\` and drops
/// a leading drive letter. UNC prefixes are not modelled.
fn file_name(path: &str, windows: bool) -> Option<&str> {
    let path = match path.as_bytes() {
        [drive, b':', ..] if windows && drive.is_ascii_alphabetic() => &path[2..],
        _ => path,
    };
    path.split(|c| c == '/' || (windows && c == '\\'))
        .rfind(|part| !part.is_empty() && *part != ".")
        .filter(|part| *part != "..")
}

/// How `verify` 0.7.6 normalizes both the member path and the input path (rule 3).
fn verify_normalized(path: &str) -> &str {
    let path = path.trim();
    path.strip_prefix("./")
        .unwrap_or(path)
        .trim_end_matches('/')
        .trim_end_matches('\\')
}

fn members<'a>(locks: &[&'a LockV0]) -> impl Iterator<Item = (usize, &'a LockMember)> {
    locks
        .iter()
        .enumerate()
        .flat_map(|(slot, lock)| lock.members.iter().map(move |member| (slot, member)))
}

/// Rules 3 and 4: members whose `key` equals `wanted`, else those sharing its basename,
/// provided they all have the same `key`.
fn one_path_pool<'a>(
    locks: &[&'a LockV0],
    wanted: &str,
    key: fn(&str) -> &str,
) -> Vec<&'a LockMember> {
    let exact: Vec<&LockMember> = members(locks)
        .map(|(_, member)| member)
        .filter(|member| key(&member.path) == wanted)
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    let name = split_basename(wanted);
    if name.is_empty() {
        return Vec::new();
    }
    let by_name: Vec<&LockMember> = members(locks)
        .map(|(_, member)| member)
        .filter(|member| split_basename(key(&member.path)) == name)
        .collect();
    let distinct: BTreeSet<&str> = by_name.iter().map(|member| key(&member.path)).collect();
    if distinct.len() == 1 {
        by_name
    } else {
        Vec::new()
    }
}

/// Rules 1 and 2: exact members, else the single (lock, member path) with the input's file name.
/// A repeated path within one lock is represented by its first entry only.
fn per_member_pool<'a>(
    locks: &[&'a LockV0],
    input_path: &str,
    windows: bool,
) -> Vec<&'a LockMember> {
    let exact_path = input_path.replace('\\', "/");
    let exact: Vec<&LockMember> = members(locks)
        .map(|(_, member)| member)
        .filter(|member| member.path == exact_path)
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    let Some(name) = file_name(input_path, windows) else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let by_name: Vec<&LockMember> = members(locks)
        .filter(|(_, member)| file_name(&member.path, windows) == Some(name))
        .filter(|(slot, member)| seen.insert((*slot, member.path.as_str())))
        .map(|(_, member)| member)
        .collect();
    if by_name.len() == 1 {
        by_name
    } else {
        Vec::new()
    }
}

/// The members each rule would check, `shape`'s Unix rule first. An empty pool means that rule
/// finds the input not locked.
fn pools<'a>(locks: &[&'a LockV0], input_path: &str) -> [Vec<&'a LockMember>; 4] {
    let earlier = input_path.replace('\\', "/");
    let earlier = earlier.strip_prefix("./").unwrap_or(&earlier);
    [
        per_member_pool(locks, input_path, false),
        per_member_pool(locks, input_path, true),
        one_path_pool(locks, verify_normalized(input_path), verify_normalized),
        one_path_pool(locks, earlier, |path| path),
    ]
}

/// The members of `lock` that name `input_path`: empty unless every rule finds at least one,
/// otherwise those `shape`'s Unix rule would check. This is NOT a verdict: do not hash these
/// yourself and call a match verified, because the other rules may check other members. Use
/// [`verify_member`].
pub fn candidates<'a>(lock: &'a LockV0, input_path: &str) -> Vec<&'a LockMember> {
    let [first, rest @ ..] = pools(&[lock], input_path);
    if rest.iter().any(Vec::is_empty) {
        Vec::new()
    } else {
        first
    }
}

/// The algorithm of a member's hash, refusing anything `verify ground` would not load.
fn usable_algorithm(member: &LockMember) -> Result<Algorithm, LockRefusal> {
    let Some(algorithm) = Algorithm::of(&member.bytes_hash) else {
        return Err(LockRefusal::UnknownAlgorithm {
            member: member.path.clone(),
            bytes_hash: member.bytes_hash.clone(),
        });
    };
    let digest = &member.bytes_hash[algorithm.prefix().len() + 1..];
    if digest.len() == HEX_DIGITS && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(algorithm)
    } else {
        Err(LockRefusal::MalformedDigest {
            member: member.path.clone(),
            bytes_hash: member.bytes_hash.clone(),
        })
    }
}

/// Check `bytes` (the content of `input_path`) against one lock. See the module docs for the
/// rule. With several locks use [`verify_member_in_locks`]; do not call this once per lock and
/// accept any success.
pub fn verify_member(
    lock: &LockV0,
    input_path: &str,
    bytes: &[u8],
) -> Result<MemberVerdict, LockRefusal> {
    verify_member_in_locks(&[lock], input_path, bytes)
}

/// Check `bytes` against several locks taken together: an exact match in any lock wins over a
/// basename match in another, and a basename found in two locks is ambiguous as it is for
/// `shape`. Each slice entry counts as its own lock, so passing one lock twice can make its own
/// basename match ambiguous (`shape` recognises a repeated file; this crate sees no files).
pub fn verify_member_in_locks(
    locks: &[&LockV0],
    input_path: &str,
    bytes: &[u8],
) -> Result<MemberVerdict, LockRefusal> {
    for (_, member) in members(locks) {
        usable_algorithm(member)?;
    }
    let pools = pools(locks, input_path);
    if pools.iter().any(Vec::is_empty) {
        return Ok(MemberVerdict::NotLocked);
    }
    let mut computed: [Option<String>; 2] = [None, None];
    let mut observed = |algorithm: Algorithm| -> String {
        computed[algorithm as usize]
            .get_or_insert_with(|| hash_bytes(algorithm, bytes))
            .clone()
    };
    let mut verified = None;
    for pool in &pools {
        let mut first_drift = None;
        let mut matched = None;
        for member in pool {
            let algorithm = usable_algorithm(member)?;
            let hash = observed(algorithm);
            if hash == member.bytes_hash {
                matched = Some(MemberVerdict::Verified {
                    member: member.path.clone(),
                    algorithm,
                });
                break;
            }
            first_drift.get_or_insert_with(|| MemberVerdict::Drift {
                member: member.path.clone(),
                expected: member.bytes_hash.clone(),
                observed: hash,
            });
        }
        match matched {
            Some(found) => verified.get_or_insert(found),
            // A non-empty pool with no match has a first drift.
            None => return Ok(first_drift.unwrap_or(MemberVerdict::NotLocked)),
        };
    }
    Ok(verified.unwrap_or(MemberVerdict::NotLocked))
}

/// The `lock_hash` of a lock document: `sha256:` over its [`sorted_compact`] form with the
/// TOP-LEVEL `lock_hash` replaced by the empty string (nested keys of that name are untouched).
/// Like `lock`, a top-level object without a `lock_hash` member gets none added.
pub fn compute_lock_hash(lock: &Value) -> String {
    let mut blanked = lock.clone();
    if let Some(slot) = blanked
        .as_object_mut()
        .and_then(|object| object.get_mut("lock_hash"))
    {
        *slot = Value::String(String::new());
    }
    hash_bytes(Algorithm::Sha256, &sorted_compact::to_vec(&blanked))
}

/// Whether the stored top-level `lock_hash` matches [`compute_lock_hash`]. A document with no
/// string `lock_hash` does not verify.
pub fn verify_lock_hash(lock: &Value) -> bool {
    lock.get("lock_hash")
        .and_then(Value::as_str)
        .is_some_and(|stored| stored == compute_lock_hash(lock))
}
