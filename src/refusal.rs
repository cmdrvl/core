//! The refusal envelope and the spine exit-code dictionary (spine-rules `docs/exit-codes.md`).
//! Refusal codes stay tool-owned strings: this crate defines their shape, not their catalogue.

use serde::Serialize;
use serde_json::Value;

use crate::sorted_compact;

/// The family exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// Positive result: PASS, no difference, ready, or a successful (possibly empty) read.
    Positive = 0,
    /// Negative result: FAIL, a real change, or an unhealthy doctor.
    Negative = 1,
    /// Refusal or CLI error: the tool did not produce a verdict.
    Refusal = 2,
    /// A valid policy verdict distinct from a refusal (for example `assess` BLOCK).
    Policy = 3,
}

impl ExitCode {
    pub const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Refusal {
    pub code: String,
    pub message: String,
    pub detail: Value,
    /// A command the caller can run next, or `null`.
    pub next_command: Option<String>,
}

/// `{"version": <tool schema version>, "outcome": "REFUSAL", "refusal": {...}}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Envelope {
    pub version: String,
    pub outcome: &'static str,
    pub refusal: Refusal,
}

impl Envelope {
    pub fn new(version: impl Into<String>, refusal: Refusal) -> Self {
        Self {
            version: version.into(),
            outcome: "REFUSAL",
            refusal,
        }
    }

    /// Deterministic text: keys sorted at every level, compact, no trailing newline.
    pub fn to_json(&self) -> String {
        // A struct of strings, an optional string and a `Value` always converts to a `Value`.
        let value = serde_json::to_value(self).expect("a refusal envelope serializes");
        sorted_compact::to_string(&value)
    }

    pub const fn exit_code(&self) -> ExitCode {
        ExitCode::Refusal
    }
}
