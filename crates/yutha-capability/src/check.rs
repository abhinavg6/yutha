//! Check types: [`ActionDescriptor`] and [`CheckOutcome`].

use std::collections::BTreeMap;
use yutha_core::Hash;

/// Describes an action being checked against a capability.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActionDescriptor {
    /// Action kind, e.g. `"envelope.send"`, `"issue_refund"`.
    pub action_kind: String,
    /// Tags on the target resource.
    pub resource_tags: Vec<String>,
    /// Numeric values being applied (e.g. refund amount). Decimal-string
    /// encoded for precision.
    pub numeric_values: BTreeMap<String, String>,
    /// For envelope-send actions: the recipient.
    pub recipient: Option<String>,
    /// For memory actions: the memory scope.
    pub memory_scope: Option<String>,
}

/// Outcome of a capability check.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    /// Whether the action is permitted.
    pub permitted: bool,
    /// On deny: a human-readable reason.
    pub deny_reason: String,
    /// Caveats that were evaluated and passed.
    pub matched_caveats: Vec<String>,
    /// Caveats that were evaluated and failed.
    pub unmet_caveats: Vec<String>,
    /// The capability id used. None if the check was performed at the
    /// scope-evaluation level without a stored capability.
    pub capability: Option<Hash>,
}

impl CheckOutcome {
    /// Construct a permit outcome.
    pub fn permit(capability: Option<Hash>, matched: Vec<String>) -> Self {
        Self {
            permitted: true,
            deny_reason: String::new(),
            matched_caveats: matched,
            unmet_caveats: vec![],
            capability,
        }
    }

    /// Construct a deny outcome with a reason.
    pub fn deny(capability: Option<Hash>, reason: impl Into<String>, unmet: Vec<String>) -> Self {
        Self {
            permitted: false,
            deny_reason: reason.into(),
            matched_caveats: vec![],
            unmet_caveats: unmet,
            capability,
        }
    }
}
