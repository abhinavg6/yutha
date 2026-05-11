//! [`Evidence`] — typed inputs/outputs of an action.
//!
//! Mirrors `Evidence` in
//! [`/spec/receipt/receipt-v1.proto`](../../../spec/receipt/receipt-v1.proto).
//!
//! Canonical evidence shapes (per receipt rationale §3) live in a separate
//! registry document (`/spec/receipt/canonical-evidence.md`, forthcoming);
//! this struct is the open-shaped container for any of them.

/// A typed key-value pair recording some input or output of an action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Evidence {
    /// Evidence key, e.g. `"envelope_hash"`, `"input_payload_digest"`,
    /// `"decision"`, `"rule_matched"`, `"deny_reason"`.
    pub key: String,
    /// `type.yutha.dev/v1/...` style URL describing the value's type.
    pub type_url: String,
    /// Serialized bytes of that type.
    pub value: Vec<u8>,
    /// If true, the evidence may carry sensitive data; verifiable backends
    /// honor selective-disclosure boundaries; observability redacts by
    /// default.
    pub sensitive: bool,
}

impl Evidence {
    /// Construct a non-sensitive evidence entry.
    pub fn new(key: impl Into<String>, type_url: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            key: key.into(),
            type_url: type_url.into(),
            value,
            sensitive: false,
        }
    }

    /// Construct a sensitive evidence entry. Verifiable backends will
    /// honor selective-disclosure boundaries on this entry.
    pub fn sensitive(key: impl Into<String>, type_url: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            key: key.into(),
            type_url: type_url.into(),
            value,
            sensitive: true,
        }
    }
}
