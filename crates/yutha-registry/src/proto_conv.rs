//! Conversions between ergonomic `yutha-registry` types and the
//! prost-generated wire types in `yutha-proto::topology::v1`.
//!
//! Both directions are required:
//!
//! - Forward (ergonomic → proto) is what `AdmissionService.GetTopology`
//!   uses to ship the swarm's topology to SDKs on startup. Agents cache
//!   the topology for the swarm's lifetime — it's immutable by spec.
//! - Reverse (proto → ergonomic) is used by operators who supply a
//!   topology document at swarm bootstrap (and, in the future, by
//!   conformance harnesses that load fixtures from disk).
//!
//! ## Fields not yet modelled
//!
//! The proto for `OpenPolicy` carries a `default_initial_scope`
//! (capability.v1.Scope) and `HybridPolicy` carries a
//! `periphery_capability_constraint` — both Scope-shaped knobs that
//! parameterize the initial capability the registry issues to a
//! newly-admitted agent. The current ergonomic types in this crate don't
//! model those (registry doesn't issue capabilities yet; capability
//! issuance lives in `yutha-capability` and is wired through the gRPC
//! `CapabilityService.Issue` path). On encode we emit `None`; on decode
//! we drop them. That's a known scaffolding gap, not a wire bug — adding
//! the field is a non-breaking ergonomic-side change because the wire
//! encoding is already forward-compatible (proto3 optional messages).

use crate::admission::{AdmissionPolicy, ClosedPolicy, HybridPolicy, OpenPolicy};
use crate::error::RegistryError;
use crate::sybil::{
    HardwareAttestationKind, HardwareAttestationRequirement, IdpAttestationRequirement,
    InviteRequirement, ProofOfWorkRequirement, StakeRequirement, SybilResistanceRequirement,
};
use crate::topology::{Topology, TopologyMode};
use yutha_core::{AgentId, CoreError, Signature, SpecVersion, SwarmId};
use yutha_passport::PassportTier;
use yutha_proto::topology::v1 as proto;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Helper: structured "required field missing" error mapped to
/// `INVALID_ARGUMENT` at the gRPC boundary via the
/// `RegistryError::Core` → `CoreError::Validation` chain.
fn missing(field: &'static str) -> RegistryError {
    RegistryError::Core(CoreError::validation(format!(
        "required field missing: {field}"
    )))
}

// =============================================================================
// FORWARD: ergonomic → proto
// =============================================================================

// -----------------------------------------------------------------------------
// TopologyMode
// -----------------------------------------------------------------------------

impl From<TopologyMode> for i32 {
    fn from(m: TopologyMode) -> Self {
        match m {
            TopologyMode::Closed => proto::TopologyMode::Closed as i32,
            TopologyMode::Open => proto::TopologyMode::Open as i32,
            TopologyMode::Hybrid => proto::TopologyMode::Hybrid as i32,
        }
    }
}

// -----------------------------------------------------------------------------
// HardwareAttestationKind
// -----------------------------------------------------------------------------

impl From<HardwareAttestationKind> for i32 {
    fn from(k: HardwareAttestationKind) -> Self {
        use proto::hardware_attestation_requirement::AttestationKind;
        match k {
            HardwareAttestationKind::Nautilus => AttestationKind::Nautilus as i32,
            HardwareAttestationKind::IntelSgx => AttestationKind::IntelSgx as i32,
            HardwareAttestationKind::AmdSev => AttestationKind::AmdSev as i32,
            HardwareAttestationKind::Tpm => AttestationKind::Tpm as i32,
        }
    }
}

// -----------------------------------------------------------------------------
// Sybil sub-types
// -----------------------------------------------------------------------------

impl From<&ProofOfWorkRequirement> for proto::ProofOfWorkRequirement {
    fn from(r: &ProofOfWorkRequirement) -> Self {
        proto::ProofOfWorkRequirement {
            difficulty_bits: r.difficulty_bits,
            challenge_prefix: r.challenge_prefix.clone(),
        }
    }
}

impl From<&HardwareAttestationRequirement> for proto::HardwareAttestationRequirement {
    fn from(r: &HardwareAttestationRequirement) -> Self {
        proto::HardwareAttestationRequirement {
            accepted_kinds: r.accepted_kinds.iter().copied().map(Into::into).collect(),
        }
    }
}

impl From<&IdpAttestationRequirement> for proto::IdpAttestationRequirement {
    fn from(r: &IdpAttestationRequirement) -> Self {
        proto::IdpAttestationRequirement {
            accepted_issuers: r.accepted_issuers.clone(),
            accepted_formats: r.accepted_formats.clone(),
        }
    }
}

impl From<&StakeRequirement> for proto::StakeRequirement {
    fn from(r: &StakeRequirement) -> Self {
        proto::StakeRequirement {
            stake_resource: r.stake_resource.clone(),
            min_stake_amount: r.min_stake_amount.clone(),
            slashing_endpoint: r.slashing_endpoint.clone(),
        }
    }
}

impl From<&InviteRequirement> for proto::InviteRequirement {
    fn from(r: &InviteRequirement) -> Self {
        proto::InviteRequirement {
            permitted_inviters: r.permitted_inviters.iter().map(Into::into).collect(),
            max_invites_per_inviter: r.max_invites_per_inviter,
            invite_window_seconds: r.invite_window_seconds,
        }
    }
}

impl From<&SybilResistanceRequirement> for proto::SybilResistanceRequirement {
    fn from(s: &SybilResistanceRequirement) -> Self {
        use proto::sybil_resistance_requirement::Kind;
        let kind = match s {
            SybilResistanceRequirement::ProofOfWork(r) => Kind::ProofOfWork(r.into()),
            SybilResistanceRequirement::HardwareAttestation(r) => {
                Kind::HardwareAttestation(r.into())
            }
            SybilResistanceRequirement::IdpAttestation(r) => Kind::IdpAttestation(r.into()),
            SybilResistanceRequirement::Stake(r) => Kind::Stake(r.into()),
            SybilResistanceRequirement::Invite(r) => Kind::Invite(r.into()),
        };
        proto::SybilResistanceRequirement { kind: Some(kind) }
    }
}

// -----------------------------------------------------------------------------
// PassportTierRequirement
// -----------------------------------------------------------------------------

/// Map an ergonomic `PassportTier` to the topology-spec's tier-requirement
/// message. Note this is a different message from `passport.v1.PassportTier`:
/// the topology spec inlines its own enum to keep the topology proto
/// independently parseable.
///
/// Naming caveat: prost strips a prefix that matches the enum's own type
/// name (`Required` → `REQUIRED_`). The proto variants here use the
/// `PASSPORT_TIER_REQUIREMENT_*` prefix which doesn't match, so prost
/// keeps the full name and the generated variants are
/// `PassportTierRequirement*`. (Same pattern as `SealStatus.State` and
/// `RegistrationResult.Status`.)
fn tier_to_requirement(t: PassportTier) -> proto::PassportTierRequirement {
    use proto::passport_tier_requirement::Required;
    let required = match t {
        PassportTier::Minimal => Required::PassportTierRequirementMinimal,
        PassportTier::Standard => Required::PassportTierRequirementStandard,
        PassportTier::Verifiable => Required::PassportTierRequirementVerifiable,
    };
    proto::PassportTierRequirement {
        required: required as i32,
    }
}

fn requirement_to_tier(r: &proto::PassportTierRequirement) -> Result<PassportTier, RegistryError> {
    use proto::passport_tier_requirement::Required;
    match Required::try_from(r.required).map_err(|_| {
        RegistryError::Core(CoreError::validation(format!(
            "unknown passport-tier-requirement: {}",
            r.required
        )))
    })? {
        Required::PassportTierRequirementUnknown => Err(RegistryError::Core(
            CoreError::validation("passport-tier-requirement unset (UNKNOWN)"),
        )),
        Required::PassportTierRequirementMinimal => Ok(PassportTier::Minimal),
        Required::PassportTierRequirementStandard => Ok(PassportTier::Standard),
        Required::PassportTierRequirementVerifiable => Ok(PassportTier::Verifiable),
    }
}

// -----------------------------------------------------------------------------
// Policy variants
// -----------------------------------------------------------------------------

impl From<&ClosedPolicy> for proto::ClosedPolicy {
    fn from(c: &ClosedPolicy) -> Self {
        proto::ClosedPolicy {
            allowlisted_agents: c.allowlisted_agents.iter().map(Into::into).collect(),
            allowlisted_owner_key_fingerprints: c.allowlisted_owner_key_fingerprints.clone(),
            pending_review_on_unknown: c.pending_review_on_unknown,
        }
    }
}

impl From<&OpenPolicy> for proto::OpenPolicy {
    fn from(o: &OpenPolicy) -> Self {
        proto::OpenPolicy {
            requirements: o.requirements.iter().map(Into::into).collect(),
            min_passport_tier: Some(tier_to_requirement(o.min_passport_tier)),
            max_passport_lifetime_seconds: o.max_passport_lifetime_seconds,
            // See module-level "Fields not yet modelled" note.
            default_initial_scope: None,
        }
    }
}

impl From<&HybridPolicy> for proto::HybridPolicy {
    fn from(h: &HybridPolicy) -> Self {
        proto::HybridPolicy {
            core: Some((&h.core).into()),
            periphery: Some((&h.periphery).into()),
            periphery_capability_constraint: None,
            periphery_may_delegate: h.periphery_may_delegate,
        }
    }
}

impl From<&AdmissionPolicy> for proto::AdmissionPolicy {
    fn from(a: &AdmissionPolicy) -> Self {
        use proto::admission_policy::Variant;
        let variant = match a {
            AdmissionPolicy::Closed(p) => Variant::Closed(p.into()),
            AdmissionPolicy::Open(p) => Variant::Open(p.into()),
            AdmissionPolicy::Hybrid(p) => Variant::Hybrid(p.into()),
        };
        proto::AdmissionPolicy {
            variant: Some(variant),
        }
    }
}

// -----------------------------------------------------------------------------
// Topology
// -----------------------------------------------------------------------------

impl From<&Topology> for proto::Topology {
    /// Encode an ergonomic [`Topology`] for the wire. Includes the operator
    /// signature if present; canonical-bytes computation (for signing) goes
    /// through a hypothetical `to_canonical_proto` once the topology spec
    /// pins down the signing path (not yet required for v1 because the
    /// registry doesn't currently re-sign topology at runtime — operators
    /// supply it pre-signed at bootstrap).
    fn from(t: &Topology) -> Self {
        proto::Topology {
            spec_version: Some((&t.spec_version).into()),
            swarm_id: Some((&t.swarm_id).into()),
            mode: t.mode.into(),
            admission: Some((&t.admission).into()),
            max_capability_lifetime_seconds: t.max_capability_lifetime_seconds,
            max_capability_chain_depth: t.max_capability_chain_depth,
            default_envelope_ttl_seconds: t.default_envelope_ttl_seconds,
            max_epoch_skew: t.max_epoch_skew,
            external_sends_permitted: t.external_sends_permitted,
            require_capability_for_send: t.require_capability_for_send,
            initial_constitution_version: t.initial_constitution_version.clone(),
            operator_key_fingerprint: t.operator_key_fingerprint.clone(),
            extensions: None,
            operator_signature: t.operator_signature.as_ref().map(Into::into),
        }
    }
}

// =============================================================================
// REVERSE: proto → ergonomic
// =============================================================================

impl TryFrom<i32> for TopologyMode {
    type Error = RegistryError;

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match proto::TopologyMode::try_from(v).map_err(|_| {
            RegistryError::Core(CoreError::validation(format!("unknown topology mode: {v}")))
        })? {
            proto::TopologyMode::Unknown => Err(RegistryError::Core(CoreError::validation(
                "topology mode unset (UNKNOWN)",
            ))),
            proto::TopologyMode::Closed => Ok(TopologyMode::Closed),
            proto::TopologyMode::Open => Ok(TopologyMode::Open),
            proto::TopologyMode::Hybrid => Ok(TopologyMode::Hybrid),
        }
    }
}

impl TryFrom<i32> for HardwareAttestationKind {
    type Error = RegistryError;

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        use proto::hardware_attestation_requirement::AttestationKind;
        match AttestationKind::try_from(v).map_err(|_| {
            RegistryError::Core(CoreError::validation(format!(
                "unknown attestation kind: {v}"
            )))
        })? {
            AttestationKind::Unknown => Err(RegistryError::Core(CoreError::validation(
                "attestation kind unset (UNKNOWN)",
            ))),
            AttestationKind::Nautilus => Ok(HardwareAttestationKind::Nautilus),
            AttestationKind::IntelSgx => Ok(HardwareAttestationKind::IntelSgx),
            AttestationKind::AmdSev => Ok(HardwareAttestationKind::AmdSev),
            AttestationKind::Tpm => Ok(HardwareAttestationKind::Tpm),
        }
    }
}

impl From<&proto::ProofOfWorkRequirement> for ProofOfWorkRequirement {
    fn from(p: &proto::ProofOfWorkRequirement) -> Self {
        ProofOfWorkRequirement {
            difficulty_bits: p.difficulty_bits,
            challenge_prefix: p.challenge_prefix.clone(),
        }
    }
}

impl TryFrom<&proto::HardwareAttestationRequirement> for HardwareAttestationRequirement {
    type Error = RegistryError;
    fn try_from(p: &proto::HardwareAttestationRequirement) -> Result<Self, Self::Error> {
        let accepted_kinds = p
            .accepted_kinds
            .iter()
            .copied()
            .map(HardwareAttestationKind::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(HardwareAttestationRequirement { accepted_kinds })
    }
}

impl From<&proto::IdpAttestationRequirement> for IdpAttestationRequirement {
    fn from(p: &proto::IdpAttestationRequirement) -> Self {
        IdpAttestationRequirement {
            accepted_issuers: p.accepted_issuers.clone(),
            accepted_formats: p.accepted_formats.clone(),
        }
    }
}

impl From<&proto::StakeRequirement> for StakeRequirement {
    fn from(p: &proto::StakeRequirement) -> Self {
        StakeRequirement {
            stake_resource: p.stake_resource.clone(),
            min_stake_amount: p.min_stake_amount.clone(),
            slashing_endpoint: p.slashing_endpoint.clone(),
        }
    }
}

impl TryFrom<&proto::InviteRequirement> for InviteRequirement {
    type Error = RegistryError;
    fn try_from(p: &proto::InviteRequirement) -> Result<Self, Self::Error> {
        let permitted_inviters = p
            .permitted_inviters
            .iter()
            .map(AgentId::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(InviteRequirement {
            permitted_inviters,
            max_invites_per_inviter: p.max_invites_per_inviter,
            invite_window_seconds: p.invite_window_seconds,
        })
    }
}

impl TryFrom<&proto::SybilResistanceRequirement> for SybilResistanceRequirement {
    type Error = RegistryError;
    fn try_from(p: &proto::SybilResistanceRequirement) -> Result<Self, Self::Error> {
        use proto::sybil_resistance_requirement::Kind;
        let kind = p
            .kind
            .as_ref()
            .ok_or_else(|| missing("sybil_resistance_requirement.kind"))?;
        Ok(match kind {
            Kind::ProofOfWork(r) => SybilResistanceRequirement::ProofOfWork(r.into()),
            Kind::HardwareAttestation(r) => {
                SybilResistanceRequirement::HardwareAttestation(r.try_into()?)
            }
            Kind::IdpAttestation(r) => SybilResistanceRequirement::IdpAttestation(r.into()),
            Kind::Stake(r) => SybilResistanceRequirement::Stake(r.into()),
            Kind::Invite(r) => SybilResistanceRequirement::Invite(r.try_into()?),
        })
    }
}

impl TryFrom<&proto::ClosedPolicy> for ClosedPolicy {
    type Error = RegistryError;
    fn try_from(p: &proto::ClosedPolicy) -> Result<Self, Self::Error> {
        let allowlisted_agents = p
            .allowlisted_agents
            .iter()
            .map(AgentId::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ClosedPolicy {
            allowlisted_agents,
            allowlisted_owner_key_fingerprints: p.allowlisted_owner_key_fingerprints.clone(),
            pending_review_on_unknown: p.pending_review_on_unknown,
        })
    }
}

impl TryFrom<&proto::OpenPolicy> for OpenPolicy {
    type Error = RegistryError;
    fn try_from(p: &proto::OpenPolicy) -> Result<Self, Self::Error> {
        let requirements = p
            .requirements
            .iter()
            .map(SybilResistanceRequirement::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let min_passport_tier = requirement_to_tier(
            p.min_passport_tier
                .as_ref()
                .ok_or_else(|| missing("open_policy.min_passport_tier"))?,
        )?;
        Ok(OpenPolicy {
            requirements,
            min_passport_tier,
            max_passport_lifetime_seconds: p.max_passport_lifetime_seconds,
        })
    }
}

impl TryFrom<&proto::HybridPolicy> for HybridPolicy {
    type Error = RegistryError;
    fn try_from(p: &proto::HybridPolicy) -> Result<Self, Self::Error> {
        let core = ClosedPolicy::try_from(
            p.core
                .as_ref()
                .ok_or_else(|| missing("hybrid_policy.core"))?,
        )?;
        let periphery = OpenPolicy::try_from(
            p.periphery
                .as_ref()
                .ok_or_else(|| missing("hybrid_policy.periphery"))?,
        )?;
        Ok(HybridPolicy {
            core,
            periphery,
            periphery_may_delegate: p.periphery_may_delegate,
        })
    }
}

impl TryFrom<&proto::AdmissionPolicy> for AdmissionPolicy {
    type Error = RegistryError;
    fn try_from(p: &proto::AdmissionPolicy) -> Result<Self, Self::Error> {
        use proto::admission_policy::Variant;
        let variant = p
            .variant
            .as_ref()
            .ok_or_else(|| missing("admission_policy.variant"))?;
        Ok(match variant {
            Variant::Closed(c) => AdmissionPolicy::Closed(c.try_into()?),
            Variant::Open(o) => AdmissionPolicy::Open(o.try_into()?),
            Variant::Hybrid(h) => AdmissionPolicy::Hybrid(h.try_into()?),
        })
    }
}

impl TryFrom<&proto::Topology> for Topology {
    type Error = RegistryError;
    fn try_from(p: &proto::Topology) -> Result<Self, Self::Error> {
        let spec_version = SpecVersion::try_from(
            p.spec_version
                .as_ref()
                .ok_or_else(|| missing("spec_version"))?,
        )?;
        let swarm_id = SwarmId::try_from(p.swarm_id.as_ref().ok_or_else(|| missing("swarm_id"))?)?;
        let mode = TopologyMode::try_from(p.mode)?;
        let admission =
            AdmissionPolicy::try_from(p.admission.as_ref().ok_or_else(|| missing("admission"))?)?;
        let operator_signature = p
            .operator_signature
            .as_ref()
            .map(Signature::try_from)
            .transpose()?;

        Ok(Topology {
            spec_version,
            swarm_id,
            mode,
            admission,
            max_capability_lifetime_seconds: p.max_capability_lifetime_seconds,
            max_capability_chain_depth: p.max_capability_chain_depth,
            default_envelope_ttl_seconds: p.default_envelope_ttl_seconds,
            max_epoch_skew: p.max_epoch_skew,
            external_sends_permitted: p.external_sends_permitted,
            require_capability_for_send: p.require_capability_for_send,
            initial_constitution_version: p.initial_constitution_version.clone(),
            operator_key_fingerprint: p.operator_key_fingerprint.clone(),
            operator_signature,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Topology {
        Topology {
            spec_version: SpecVersion::parse("1.0.0").unwrap(),
            swarm_id: SwarmId::new(),
            mode: TopologyMode::Closed,
            admission: AdmissionPolicy::Closed(ClosedPolicy {
                allowlisted_agents: vec![AgentId::new()],
                allowlisted_owner_key_fingerprints: vec![vec![0xab; 32]],
                pending_review_on_unknown: true,
            }),
            max_capability_lifetime_seconds: 86_400,
            max_capability_chain_depth: 8,
            default_envelope_ttl_seconds: 300,
            max_epoch_skew: 64,
            external_sends_permitted: false,
            require_capability_for_send: false,
            initial_constitution_version: "1.0.0".into(),
            operator_key_fingerprint: vec![0xcd; 32],
            operator_signature: None,
        }
    }

    #[test]
    fn topology_round_trips_through_proto() {
        let original = fixture();
        let p: proto::Topology = (&original).into();
        let back = Topology::try_from(&p).expect("reverse should succeed");
        assert_eq!(back, original);
    }

    #[test]
    fn open_policy_round_trips() {
        let original = Topology {
            mode: TopologyMode::Open,
            admission: AdmissionPolicy::Open(OpenPolicy {
                requirements: vec![SybilResistanceRequirement::Invite(InviteRequirement {
                    permitted_inviters: vec![AgentId::new()],
                    max_invites_per_inviter: 5,
                    invite_window_seconds: 3600,
                })],
                min_passport_tier: PassportTier::Standard,
                max_passport_lifetime_seconds: 7 * 24 * 60 * 60,
            }),
            ..fixture()
        };
        let p: proto::Topology = (&original).into();
        let back = Topology::try_from(&p).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn hybrid_policy_round_trips() {
        let original = Topology {
            mode: TopologyMode::Hybrid,
            admission: AdmissionPolicy::Hybrid(HybridPolicy {
                core: ClosedPolicy {
                    allowlisted_agents: vec![AgentId::new()],
                    ..Default::default()
                },
                periphery: OpenPolicy::default(),
                periphery_may_delegate: true,
            }),
            ..fixture()
        };
        let p: proto::Topology = (&original).into();
        let back = Topology::try_from(&p).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn topology_mode_unknown_rejected() {
        assert!(TopologyMode::try_from(0).is_err());
        assert!(TopologyMode::try_from(99).is_err());
    }

    #[test]
    fn missing_admission_rejected() {
        let t = fixture();
        let mut p: proto::Topology = (&t).into();
        p.admission = None;
        let err = Topology::try_from(&p).unwrap_err();
        assert!(matches!(err, RegistryError::Core(_)));
        assert!(err.to_string().contains("admission"));
    }
}
