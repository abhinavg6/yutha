//! [`Topology`] and [`TopologyMode`].

use crate::admission::AdmissionPolicy;
use yutha_core::{Signature, SpecVersion, SwarmId};

/// Coarse participation mode for a swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TopologyMode {
    /// Allowlist-based; trusted-only.
    Closed,
    /// Anyone meeting sybil-resistance criteria.
    Open,
    /// Trusted core + open periphery.
    Hybrid,
}

/// Swarm-mode declaration with admission policy and default knobs.
/// Immutable for the swarm's lifetime — changing requires creating a new
/// swarm and migrating.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Topology {
    /// Spec version.
    pub spec_version: SpecVersion,
    /// Swarm this topology applies to.
    pub swarm_id: SwarmId,
    /// Participation mode.
    pub mode: TopologyMode,
    /// Admission policy. Variant must agree with `mode`.
    pub admission: AdmissionPolicy,
    /// Default capability lifetime ceiling (seconds).
    pub max_capability_lifetime_seconds: u64,
    /// Maximum capability attenuation chain depth.
    pub max_capability_chain_depth: u32,
    /// Default envelope TTL when sender omits expires_at.
    pub default_envelope_ttl_seconds: u64,
    /// Replay protection epoch tolerance.
    pub max_epoch_skew: u32,
    /// Whether external-endpoint sends are permitted (subject to capability).
    pub external_sends_permitted: bool,
    /// When true, every `EnvelopeService.Send` MUST present a
    /// `SendEnvelopeRequest.capability_id` and pass the server-side
    /// capability check; deny rejects with `PERMISSION_DENIED`. When
    /// false, sends without a cap are accepted (legacy v1.0 behavior);
    /// a cap supplied anyway is still checked and audited.
    ///
    /// Defaults at registry construction (set by the operator binary,
    /// not by `Topology` itself): closed → true, open → false, hybrid
    /// → operator-set. See RFC 0007.
    pub require_capability_for_send: bool,
    /// Genesis constitution version.
    pub initial_constitution_version: String,
    /// Operator-key fingerprint (trust root).
    pub operator_key_fingerprint: Vec<u8>,
    /// Operator's signature over the canonical form.
    pub operator_signature: Option<Signature>,
}

impl Topology {
    /// Check that the mode and admission policy agree (e.g., CLOSED ↔
    /// ClosedPolicy).
    pub fn is_consistent(&self) -> bool {
        matches!(
            (self.mode, &self.admission),
            (TopologyMode::Closed, AdmissionPolicy::Closed(_))
                | (TopologyMode::Open, AdmissionPolicy::Open(_))
                | (TopologyMode::Hybrid, AdmissionPolicy::Hybrid(_))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{ClosedPolicy, HybridPolicy, OpenPolicy};

    fn empty_topology(mode: TopologyMode, admission: AdmissionPolicy) -> Topology {
        Topology {
            spec_version: SpecVersion::parse("1.0.0").unwrap(),
            swarm_id: SwarmId::new(),
            mode,
            admission,
            max_capability_lifetime_seconds: 90 * 24 * 60 * 60,
            max_capability_chain_depth: 8,
            default_envelope_ttl_seconds: 300,
            max_epoch_skew: 256,
            external_sends_permitted: false,
            require_capability_for_send: false,
            initial_constitution_version: "1.0.0".into(),
            operator_key_fingerprint: vec![0u8; 32],
            operator_signature: None,
        }
    }

    #[test]
    fn closed_matches_closed_policy() {
        let t = empty_topology(
            TopologyMode::Closed,
            AdmissionPolicy::Closed(ClosedPolicy::default()),
        );
        assert!(t.is_consistent());
    }

    #[test]
    fn closed_mismatches_open_policy() {
        let t = empty_topology(
            TopologyMode::Closed,
            AdmissionPolicy::Open(OpenPolicy::default()),
        );
        assert!(!t.is_consistent());
    }

    #[test]
    fn hybrid_matches_hybrid_policy() {
        let t = empty_topology(
            TopologyMode::Hybrid,
            AdmissionPolicy::Hybrid(HybridPolicy::default()),
        );
        assert!(t.is_consistent());
    }
}
