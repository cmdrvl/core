//! `<algorithm>:<lowercase hex>` content hashes over raw bytes.
//!
//! Policy (spine-rules `docs/hashing-policy.md`): `blake3:` is the canonical spine hash,
//! `sha256:` is supported for external and legacy interoperability, and verification always uses
//! the algorithm the recorded hash names.

use std::fmt;

use sha2::{Digest, Sha256};

/// Hex digits in a BLAKE3 or SHA-256 digest.
pub const HEX_DIGITS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Blake3,
    Sha256,
}

impl Algorithm {
    /// The algorithm named by the prefix of `hash`, if supported. Looks at the prefix only (the
    /// spine-rules lock verifier's behaviour); use [`parse_prefixed`] to also check the digest.
    pub fn of(hash: &str) -> Option<Self> {
        match hash.split_once(':')?.0 {
            "blake3" => Some(Self::Blake3),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }

    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
        }
    }
}

/// `<algorithm>:<lowercase hex>` of `bytes`.
pub fn hash_bytes(algorithm: Algorithm, bytes: &[u8]) -> String {
    match algorithm {
        Algorithm::Blake3 => format!("blake3:{}", blake3::hash(bytes).to_hex()),
        Algorithm::Sha256 => format!("sha256:{:x}", Sha256::digest(bytes)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashError {
    /// No `blake3:` or `sha256:` prefix. The hash is refused, never guessed.
    UnknownAlgorithm,
    /// The digest is not exactly [`HEX_DIGITS`] lowercase hex digits.
    BadDigest,
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownAlgorithm => "unknown hash algorithm prefix (want blake3: or sha256:)",
            Self::BadDigest => "hash digest must be 64 lowercase hex digits",
        })
    }
}

impl std::error::Error for HashError {}

/// Strictly parse `blake3:<64 lowercase hex>` or `sha256:<64 lowercase hex>`, returning the
/// algorithm and the hex. Stricter than the lock verifier (which compares strings), for new
/// callers that accept a hash as input.
pub fn parse_prefixed(hash: &str) -> Result<(Algorithm, &str), HashError> {
    let algorithm = Algorithm::of(hash).ok_or(HashError::UnknownAlgorithm)?;
    let hex = &hash[algorithm.prefix().len() + 1..];
    if hex.len() == HEX_DIGITS && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok((algorithm, hex))
    } else {
        Err(HashError::BadDigest)
    }
}
