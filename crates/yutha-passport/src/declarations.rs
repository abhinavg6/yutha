//! [`CapabilityDeclaration`] and [`ResourceDeclaration`].
//!
//! Mirrors the same-named messages in
//! [`/spec/passport/passport-v1.proto`](../../../spec/passport/passport-v1.proto).
//!
//! **Critical:** these are *declarations*. Authority comes from the
//! [Capability spec](../../../spec/capability/) — what the agent claims it
//! can do is not what it's permitted to do. The registry uses these as
//! inputs to admission policy, not as authority grants.

use std::collections::BTreeMap;

/// What the agent claims it can perform.
///
/// The registry MAY admit the declaration as-is in closed mode, MAY require
/// attestation in open mode, MAY apply periphery constraints in hybrid mode
/// (see [`/spec/topology/`](../../../spec/topology/)).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CapabilityDeclaration {
    /// Canonical action-kind string. Examples: `"send_message"`,
    /// `"read_shared_memory"`, `"call_tool"`, `"issue_refund"`.
    pub kind: String,
    /// Resource scope this capability applies to. Free-form structured
    /// tags. Constitution norms are evaluated against these at runtime.
    pub resource_tags: Vec<String>,
    /// Numeric bounds (decimal-string-encoded for precision). Example:
    /// `{"usd_max": "500"}` for a refund-capable role.
    pub bounds: BTreeMap<String, String>,
    /// Human-readable description.
    pub description: String,
}

impl CapabilityDeclaration {
    /// Construct a minimal declaration with just an action kind.
    pub fn of_kind(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            resource_tags: vec![],
            bounds: BTreeMap::new(),
            description: String::new(),
        }
    }

    /// Builder: add a resource tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.resource_tags.push(tag.into());
        self
    }

    /// Builder: set a numeric bound.
    pub fn with_bound(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.bounds.insert(key.into(), value.into());
        self
    }

    /// Builder: set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// What budget the agent declares it expects.
///
/// The control plane MAY enforce these as caps; the constitution can
/// additionally constrain. Per PRD §13.4 "blast-radius bounds."
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceDeclaration {
    /// Max concurrent actions in flight.
    pub max_concurrent_actions: u64,
    /// Rate ceiling: messages per minute.
    pub max_messages_per_minute: u64,
    /// Rate ceiling: tool calls per hour.
    pub max_tool_calls_per_hour: u64,
    /// USD cost ceiling per day, decimal-string-encoded (e.g. `"100.00"`).
    pub max_usd_per_day_cents: String,
    /// Memory footprint cap.
    pub max_memory_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_builder_fluent() {
        let d = CapabilityDeclaration::of_kind("issue_refund")
            .with_tag("finance")
            .with_bound("usd_max", "500.00")
            .with_description("Issues refunds up to $500");
        assert_eq!(d.kind, "issue_refund");
        assert_eq!(d.resource_tags, vec!["finance"]);
        assert_eq!(d.bounds.get("usd_max"), Some(&"500.00".to_string()));
        assert_eq!(d.description, "Issues refunds up to $500");
    }

    #[test]
    fn resource_declaration_default_is_zero() {
        let r = ResourceDeclaration::default();
        assert_eq!(r.max_concurrent_actions, 0);
        assert_eq!(r.max_usd_per_day_cents, "");
    }
}
