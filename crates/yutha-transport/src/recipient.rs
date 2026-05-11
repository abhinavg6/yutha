//! [`Recipient`] — who an envelope is addressed to.

use yutha_core::AgentId;

/// Four kinds of recipient. External endpoints require capability tokens to
/// authorize; the topology mode may forbid them entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Recipient {
    /// A specific agent (unicast).
    Agent(AgentId),
    /// All agents currently bound to this role.
    Role(String),
    /// A swarm-wide broadcast.
    Swarm(SwarmBroadcast),
    /// An external endpoint (always requires capability).
    External(ExternalEndpoint),
}

/// Swarm-wide broadcast with optional tag filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SwarmBroadcast {
    /// If non-empty, only agents matching all filter tags receive.
    pub filter_tags: Vec<String>,
}

/// External endpoint descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalEndpoint {
    /// Scheme (e.g. `"https"`, `"smtp"`).
    pub scheme: String,
    /// Authority (e.g. `"api.example.com"`).
    pub authority: String,
    /// Coarse routing hint (the capability decides the full URL).
    pub path_hint: String,
}
