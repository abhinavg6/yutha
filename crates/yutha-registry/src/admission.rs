//! [`AdmissionPolicy`] — three variants matching the three [`crate::TopologyMode`]s.

use crate::sybil::SybilResistanceRequirement;
use yutha_core::AgentId;
use yutha_passport::PassportTier;

/// Admission policy. Variant must match the topology's mode.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AdmissionPolicy {
    /// Closed: allowlist of agent ids and/or owner-key fingerprints.
    Closed(ClosedPolicy),
    /// Open: anyone meeting sybil-resistance criteria.
    Open(OpenPolicy),
    /// Hybrid: trusted closed core + open periphery.
    Hybrid(HybridPolicy),
}

/// Closed admission: known-list of agents / owner-keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClosedPolicy {
    /// Allowlisted agent ids.
    pub allowlisted_agents: Vec<AgentId>,
    /// Allowlisted owner-key fingerprints (SHA-256, 32 bytes each).
    pub allowlisted_owner_key_fingerprints: Vec<Vec<u8>>,
    /// If true, unknown ids go to PENDING_REVIEW; if false, REJECTED.
    pub pending_review_on_unknown: bool,
}

/// Open admission: sybil-resistance + min tier + lifetime cap.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OpenPolicy {
    /// ALL requirements must be met.
    pub requirements: Vec<SybilResistanceRequirement>,
    /// Required minimum passport tier.
    pub min_passport_tier: PassportTier,
    /// Max passport lifetime in seconds (open swarms tighten from default).
    pub max_passport_lifetime_seconds: u64,
    // default_initial_scope is intentionally omitted at the registry layer;
    // it's enforced when the registry issues post-registration capabilities
    // through yutha-capability.
}

impl Default for OpenPolicy {
    fn default() -> Self {
        Self {
            requirements: vec![],
            min_passport_tier: PassportTier::Standard,
            max_passport_lifetime_seconds: 7 * 24 * 60 * 60,
        }
    }
}

/// Hybrid admission: closed core + open periphery + periphery scope cap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridPolicy {
    /// Closed core admission rules.
    pub core: ClosedPolicy,
    /// Open periphery admission rules.
    pub periphery: OpenPolicy,
    /// Whether periphery agents may attenuate-delegate. Default false
    /// (periphery is leaf-only).
    pub periphery_may_delegate: bool,
}
