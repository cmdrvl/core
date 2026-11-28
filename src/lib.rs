//! # cmdrvl-core
//!
//! Zero-I/O primitives shared by CMD+RVL tools. Callers pass bytes and values; this crate reads
//! no file, environment variable or clock, spawns nothing and uses no randomness, so the same
//! input gives the same output on every platform, including `wasm32-unknown-unknown`.
//!
//! - [`jcs`]: RFC 8785 canonical JSON.
//! - [`sorted_compact`]: the sorted compact form `lock` and `pack` hash today. Not RFC 8785.
//! - [`hash`]: `blake3:` / `sha256:` prefixed hashes.
//! - [`lockfile`]: `lock.v0` member verification and the lock's own self-hash.
//! - [`lock_matching`]: the pure names-and-digests R1 matching rule for consumers.
//! - [`refusal`]: refusal envelope and the spine exit-code dictionary.
//! - [`contract`]: a content hash of a JSON contract document.
//! - [`redact`]: zero-retention markers (ordinal refs by default, keyed HMAC on request).

#![forbid(unsafe_code)]

pub mod contract;
pub mod exact_decimal;
pub mod hash;
pub mod jcs;
pub mod lock_matching;
pub mod lockfile;
pub mod redact;
pub mod refusal;
pub mod sorted_compact;
