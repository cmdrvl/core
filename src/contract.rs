//! A content hash that identifies a JSON contract document (a policy, a manifest, a schema).
//!
//! No tool has a shared type for this today; `airlock` computes `blake3(JCS(value))`
//! (`jcs_blake3_hash`), which [`ContractHash::of_jcs`] reproduces.

use std::fmt;

use serde_json::Value;

use crate::hash::{Algorithm, HashError, hash_bytes, parse_prefixed};
use crate::jcs::{self, JcsError};

/// A strictly valid `<algorithm>:<64 lowercase hex>` hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContractHash(String);

impl ContractHash {
    /// `blake3(JCS(value))`. Fails where RFC 8785 cannot represent the value.
    pub fn of_jcs(value: &Value) -> Result<Self, JcsError> {
        Ok(Self(hash_bytes(Algorithm::Blake3, &jcs::to_vec(value)?)))
    }

    /// Accept a recorded hash, strictly (see [`parse_prefixed`]).
    pub fn parse(text: &str) -> Result<Self, HashError> {
        parse_prefixed(text)?;
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContractHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
