//! `lock.v0` verification.
//!
//! Member verification has the semantics of `spine_rules::lockfile` (commit 2d1e23a), unchanged:
//!
//! - `members[].bytes_hash` is `<algorithm>:<lowercase hex>` of the RAW file bytes;
//! - a member matches an input by exact path, otherwise by a unique basename; an ambiguous
//!   basename matches nothing;
//! - the input is hashed with the MEMBER'S algorithm; different text is drift; no member is "not
//!   locked"; an unknown algorithm on a matched member is refused.
//!
//! This crate does not depend on spine-rules (spine-rules may depend on it later). The
//! conformance cases in `tests/lockfile_conformance.rs` are a copy of spine-rules' cases, which
//! keeps the two equal until then.
//!
//! The lock's own `lock_hash` self-hash is checked separately by [`verify_lock_hash`], which
//! reproduces `lock` (`src/lockfile/self_hash.rs`, commit 8c0cdd9).

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::Value;

use crate::hash::{Algorithm, hash_bytes};
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
    /// A matched member names an algorithm other than `blake3` or `sha256`.
    UnknownAlgorithm {
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

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or("")
}

/// Members that vouch for `input_path`: exact path match wins, else a unique basename.
pub fn candidates<'a>(lock: &'a LockV0, input_path: &str) -> Vec<&'a LockMember> {
    let normalized = input_path.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    let exact: Vec<&LockMember> = lock
        .members
        .iter()
        .filter(|member| member.path == normalized)
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    let wanted = basename(normalized);
    if wanted.is_empty() {
        return Vec::new();
    }
    let by_name: Vec<&LockMember> = lock
        .members
        .iter()
        .filter(|member| basename(&member.path) == wanted)
        .collect();
    let distinct: BTreeSet<&str> = by_name.iter().map(|member| member.path.as_str()).collect();
    if distinct.len() == 1 {
        by_name
    } else {
        Vec::new()
    }
}

/// Check `bytes` (the content of `input_path`) against `lock`.
pub fn verify_member(
    lock: &LockV0,
    input_path: &str,
    bytes: &[u8],
) -> Result<MemberVerdict, LockRefusal> {
    let mut first_drift: Option<MemberVerdict> = None;
    for member in candidates(lock, input_path) {
        let Some(algorithm) = Algorithm::of(&member.bytes_hash) else {
            return Err(LockRefusal::UnknownAlgorithm {
                member: member.path.clone(),
                bytes_hash: member.bytes_hash.clone(),
            });
        };
        let observed = hash_bytes(algorithm, bytes);
        if observed == member.bytes_hash {
            return Ok(MemberVerdict::Verified {
                member: member.path.clone(),
                algorithm,
            });
        }
        first_drift.get_or_insert(MemberVerdict::Drift {
            member: member.path.clone(),
            expected: member.bytes_hash.clone(),
            observed,
        });
    }
    Ok(first_drift.unwrap_or(MemberVerdict::NotLocked))
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
