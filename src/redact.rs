//! Zero-retention markers: deterministic ordinal refs by default, keyed HMAC-SHA256 on request.
//!
//! - **Ordinal** (default): `redacted:ref:<letter><n>`, numbered from 1 per [`Namespace`] in the
//!   order first marked; equal bytes share a ref. No hash of anything is computed, so nothing can
//!   be guessed from a dictionary. A ref shows only the equality pattern inside one output, and
//!   output is byte-identical when the same input is processed again. Mark in DATA order, never
//!   in value order, or the numbers reveal the sort order.
//! - **Keyed**: `redacted:hmac-sha256:<32 hex>`, the first 128 bits of HMAC-SHA256(key, input),
//!   stable across runs for the key holder. The input depends on the [`Scheme`], because the
//!   existing tools disagree and their markers must not change:
//!
//! | Scheme | HMAC input | Used today by |
//! |---|---|---|
//! | [`Scheme::Raw`] | the bytes as given (a row key tuple: [`frame_components`]) | `rvl`; `verify` (bytes = serde_json text of the value) |
//! | [`Scheme::Tagged`] | namespace tag, one `0x00`, the bytes | `profile` (`column`), `fingerprint` (all name kinds) |
//!
//! `Raw` has no domain separation: equal bytes in different namespaces give equal keyed markers.
//! `benchmark` and `decoding` print other text (`hmac-sha256:` with 32 or 64 hex); they can be
//! reproduced with [`RedactionKey::hmac_sha256`], and this crate adds no second marker format.
//!
//! This crate reads no environment variable. A tool passes the bytes it read. A set but unusable
//! key is an error: there is no path from a bad key to ordinal refs.

use std::collections::BTreeMap;
use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const MIN_KEY_BYTES: usize = 16;
pub const REF_PREFIX: &str = "redacted:ref:";
pub const HMAC_PREFIX: &str = "redacted:hmac-sha256:";
/// The family-wide variable name a tool may fall back to (see [`select_key`]). Only a name.
pub const FALLBACK_ENV: &str = "CMDRVL_REDACTION_KEY";

/// Why a key was refused. Never carries the key or its length. Refusal codes stay tool-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Empty,
    TooShort,
}

impl KeyError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooShort => "too_short",
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "redaction key refused: {}", self.reason())
    }
}

impl std::error::Error for KeyError {}

/// An operator-held key of at least [`MIN_KEY_BYTES`] bytes. `Debug` never prints it.
#[derive(Clone)]
pub struct RedactionKey(Vec<u8>);

impl fmt::Debug for RedactionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactionKey(<withheld>)")
    }
}

impl RedactionKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeyError> {
        if bytes.is_empty() {
            Err(KeyError::Empty)
        } else if bytes.len() < MIN_KEY_BYTES {
            Err(KeyError::TooShort)
        } else {
            Ok(Self(bytes))
        }
    }

    /// `None` (variable unset) means ordinal refs; set but empty or short is an error.
    pub fn from_optional(value: Option<&[u8]>) -> Result<Option<Self>, KeyError> {
        value.map(|bytes| Self::new(bytes.to_vec())).transpose()
    }

    /// HMAC-SHA256 of `input` under this key (all 32 bytes).
    pub fn hmac_sha256(&self, input: &[u8]) -> [u8; 32] {
        self.hmac_parts(&[input])
    }

    fn hmac_parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        // HMAC accepts a key of any length, so construction cannot fail.
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts a key of any length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    /// [`Scheme::Raw`] marker over `input`.
    pub fn marker_raw(&self, input: &[u8]) -> String {
        marker_text(&self.hmac_sha256(input))
    }

    /// [`Scheme::Tagged`] marker over `tag`, `0x00`, `input`.
    pub fn marker_tagged(&self, tag: &str, input: &[u8]) -> String {
        marker_text(&self.hmac_parts(&[tag.as_bytes(), &[0], input]))
    }
}

fn marker_text(digest: &[u8; 32]) -> String {
    let mut text = String::from(HMAC_PREFIX);
    for byte in &digest[..16] {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// The tool's own variable wins whenever it is SET, even to an empty or short value (which is
/// then an error: it never falls through to the fallback or to ordinal refs). The fallback is
/// consulted only when the tool's variable is unset.
pub fn select_key(
    tool_value: Option<&[u8]>,
    fallback_value: Option<&[u8]>,
) -> Result<Option<RedactionKey>, KeyError> {
    RedactionKey::from_optional(tool_value.or(fallback_value))
}

/// Length-framed bytes of a tuple: each part as a little-endian `u64` length followed by the
/// bytes, so `("ab","c")` and `("a","bc")` differ. This is `rvl`'s row-key framing.
pub fn frame_components<T: AsRef<[u8]>>(parts: &[T]) -> Vec<u8> {
    let mut framed = Vec::new();
    for part in parts {
        let part = part.as_ref();
        framed.extend_from_slice(&(part.len() as u64).to_le_bytes());
        framed.extend_from_slice(part);
    }
    framed
}

/// A kind of redacted thing: its own ordinal numbering, its ref letter, and its HMAC domain tag
/// for [`Scheme::Tagged`]. Letters are not unique across tools: `k` is a row key in `rvl` and
/// `verify` ([`Namespace::ROW`]) and a metadata key in `fingerprint`
/// ([`Namespace::METADATA_KEY`]); one output should not use both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Namespace {
    pub tag: &'static str,
    pub letter: char,
}

impl Namespace {
    pub const ROW: Self = Self::new("row", 'k');
    pub const VALUE: Self = Self::new("value", 'v');
    pub const COLUMN: Self = Self::new("column", 'c');
    pub const SHEET: Self = Self::new("sheet", 's');
    pub const HEADING: Self = Self::new("heading", 'h');
    pub const PATH: Self = Self::new("path", 'p');
    pub const METADATA_KEY: Self = Self::new("metadata_key", 'k');
    pub const OUTLINE: Self = Self::new("outline", 'o');
    pub const NAMESPACE: Self = Self::new("namespace", 'n');

    pub const fn new(tag: &'static str, letter: char) -> Self {
        Self { tag, letter }
    }
}

/// How a keyed marker's HMAC input is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Raw,
    Tagged,
}

/// Turns bytes into markers for ONE output. Mark in the order the data appears.
#[derive(Debug)]
pub struct Marker<'a> {
    keyed: Option<(&'a RedactionKey, Scheme)>,
    seen: BTreeMap<Namespace, BTreeMap<Vec<u8>, usize>>,
}

impl<'a> Marker<'a> {
    pub fn ordinal() -> Self {
        Self {
            keyed: None,
            seen: BTreeMap::new(),
        }
    }

    pub fn keyed(key: &'a RedactionKey, scheme: Scheme) -> Self {
        Self {
            keyed: Some((key, scheme)),
            seen: BTreeMap::new(),
        }
    }

    /// Ordinal refs when `key` is `None`, keyed markers otherwise.
    pub fn new(key: Option<&'a RedactionKey>, scheme: Scheme) -> Self {
        match key {
            Some(key) => Self::keyed(key, scheme),
            None => Self::ordinal(),
        }
    }

    pub fn is_keyed(&self) -> bool {
        self.keyed.is_some()
    }

    pub fn mark(&mut self, namespace: Namespace, bytes: &[u8]) -> String {
        match self.keyed {
            Some((key, Scheme::Raw)) => key.marker_raw(bytes),
            Some((key, Scheme::Tagged)) => key.marker_tagged(namespace.tag, bytes),
            None => {
                let ordinal = self.ordinal_of(namespace, bytes);
                format!("{REF_PREFIX}{}{ordinal}", namespace.letter)
            }
        }
    }

    /// The 1-based first-appearance number of `bytes` in `namespace`, for a caller with its own
    /// ref text. Shares numbering with [`Marker::mark`] in ordinal mode.
    pub fn ordinal_of(&mut self, namespace: Namespace, bytes: &[u8]) -> usize {
        let table = self.seen.entry(namespace).or_default();
        let next = table.len() + 1;
        *table.entry(bytes.to_vec()).or_insert(next)
    }
}
