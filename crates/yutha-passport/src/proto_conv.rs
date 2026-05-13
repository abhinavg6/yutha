//! Conversions between ergonomic [`yutha-passport`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! The forward direction (ergonomic → proto) is used for content-addressing
//! and signature verification through [`Passport::to_canonical_proto`].
//!
//! The reverse direction (proto → ergonomic) is used by the control-plane
//! gRPC handlers when decoding `RegisterRequest` and `RotateKeyRequest`
//! payloads, and for synthesizing `RegistrationResult` responses from the
//! ergonomic [`RegistrationOutcome`]. Reverse conversions are fallible
//! because the wire shape uses `Option<T>` for nested messages and unknown
//! enum variants that the ergonomic types reject up front.

use crate::{
    CapabilityDeclaration, Passport, PassportError, PassportTier, RegistrationOutcome,
    RegistrationStatus, ResourceDeclaration,
};
use yutha_core::{AgentId, CoreError, PublicKey, Signature, SpecVersion, SwarmId, Timestamp};
use yutha_proto::passport::v1 as proto;

// -----------------------------------------------------------------------------
// PassportTier
// -----------------------------------------------------------------------------

impl From<PassportTier> for i32 {
    fn from(t: PassportTier) -> Self {
        // proto enum variants are `PASSPORT_TIER_*`; prost strips the
        // `PASSPORT_TIER_` prefix (matches the enum's own type name)
        // cleanly. Result: `Minimal`, `Standard`, `Verifiable`.
        match t {
            PassportTier::Minimal => proto::PassportTier::Minimal as i32,
            PassportTier::Standard => proto::PassportTier::Standard as i32,
            PassportTier::Verifiable => proto::PassportTier::Verifiable as i32,
        }
    }
}

// -----------------------------------------------------------------------------
// CapabilityDeclaration
// -----------------------------------------------------------------------------

impl From<&CapabilityDeclaration> for proto::CapabilityDeclaration {
    fn from(d: &CapabilityDeclaration) -> Self {
        proto::CapabilityDeclaration {
            kind: d.kind.clone(),
            resource_tags: d.resource_tags.clone(),
            // `bounds` is generated as `BTreeMap<String, String>` thanks to
            // `btree_map(["."])` in yutha-proto's build.rs, which gives us
            // sorted-key encoding for free.
            bounds: d.bounds.clone(),
            description: d.description.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// ResourceDeclaration
// -----------------------------------------------------------------------------

impl From<&ResourceDeclaration> for proto::ResourceDeclaration {
    fn from(r: &ResourceDeclaration) -> Self {
        proto::ResourceDeclaration {
            max_concurrent_actions: r.max_concurrent_actions,
            max_messages_per_minute: r.max_messages_per_minute,
            max_tool_calls_per_hour: r.max_tool_calls_per_hour,
            max_usd_per_day_cents: r.max_usd_per_day_cents.clone(),
            max_memory_bytes: r.max_memory_bytes,
        }
    }
}

// -----------------------------------------------------------------------------
// Passport
// -----------------------------------------------------------------------------

impl From<&Passport> for proto::Passport {
    /// Convert an ergonomic [`Passport`] into its wire form. Includes
    /// `agent_signature` if present; [`Passport::to_canonical_proto`] is what
    /// clears it for content-addressing.
    fn from(p: &Passport) -> Self {
        proto::Passport {
            spec_version: Some((&p.spec_version).into()),
            agent_id: Some((&p.agent_id).into()),
            swarm_id: Some((&p.swarm_id).into()),
            agent_public_key: Some((&p.agent_public_key).into()),
            owner: p.owner.clone(),
            framework: p.framework.clone(),
            framework_version: p.framework_version.clone(),
            capabilities: p.capabilities.iter().map(Into::into).collect(),
            accepted_constitution_version: p.accepted_constitution_version.clone(),
            tier: p.tier.into(),
            resources: Some((&p.resources).into()),
            issued_at: Some((&p.issued_at).into()),
            expires_at: p.expires_at.as_ref().map(Into::into),
            default_model_provider: p.default_model_provider.clone(),
            default_model_name: p.default_model_name.clone(),
            extensions: None,
            agent_signature: p.agent_signature.as_ref().map(Into::into),
        }
    }
}

impl Passport {
    /// Canonical proto representation for content-addressing.
    ///
    /// Clears `agent_signature` (the field that the canonical bytes are
    /// signed over — circular if included) and drops `extensions` for v1.0
    /// for the same reason it's dropped in `Receipt::to_canonical_proto`
    /// (vendor extensions don't participate in content-addressing until a
    /// stabilizing RFC says they do).
    pub fn to_canonical_proto(&self) -> proto::Passport {
        let mut p: proto::Passport = self.into();
        p.agent_signature = None;
        p.extensions = None;
        p
    }
}

// =============================================================================
// REVERSE: proto → ergonomic
// =============================================================================
//
// Reverse conversions are fallible (`TryFrom`) for the same reasons as the
// receipt crate: proto3 nested messages are `Option<T>`; unknown enum values
// are rejected; typed-wrapper validation runs at conversion time.

/// Helper: turn a required-but-missing proto field into a structured error.
/// Wraps `CoreError::Validation` so the gRPC layer maps it to
/// `INVALID_ARGUMENT`.
fn missing(field: &'static str) -> PassportError {
    PassportError::Core(CoreError::validation(format!(
        "required field missing: {field}"
    )))
}

// -----------------------------------------------------------------------------
// PassportTier
// -----------------------------------------------------------------------------

impl TryFrom<i32> for PassportTier {
    type Error = PassportError;

    /// Decode the wire tier. Rejects UNKNOWN (0) — peers must send a concrete
    /// tier — and any future value we don't yet allocate.
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match proto::PassportTier::try_from(v).map_err(|_| {
            PassportError::Core(CoreError::validation(format!("unknown passport tier: {v}")))
        })? {
            proto::PassportTier::Unknown => Err(PassportError::Core(CoreError::validation(
                "passport tier unset (UNKNOWN)",
            ))),
            proto::PassportTier::Minimal => Ok(PassportTier::Minimal),
            proto::PassportTier::Standard => Ok(PassportTier::Standard),
            proto::PassportTier::Verifiable => Ok(PassportTier::Verifiable),
        }
    }
}

// -----------------------------------------------------------------------------
// CapabilityDeclaration
// -----------------------------------------------------------------------------

impl From<&proto::CapabilityDeclaration> for CapabilityDeclaration {
    /// CapabilityDeclaration has no required nested messages or enums, so
    /// `From` (infallible) is appropriate. The `bounds` field on the wire
    /// is `BTreeMap<String, String>` (via `btree_map(["."])` in
    /// `yutha-proto`'s build); we keep that type to preserve sorted-key
    /// determinism if/when callers re-encode.
    fn from(p: &proto::CapabilityDeclaration) -> Self {
        CapabilityDeclaration {
            kind: p.kind.clone(),
            resource_tags: p.resource_tags.clone(),
            bounds: p.bounds.clone(),
            description: p.description.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// ResourceDeclaration
// -----------------------------------------------------------------------------

impl From<&proto::ResourceDeclaration> for ResourceDeclaration {
    fn from(p: &proto::ResourceDeclaration) -> Self {
        ResourceDeclaration {
            max_concurrent_actions: p.max_concurrent_actions,
            max_messages_per_minute: p.max_messages_per_minute,
            max_tool_calls_per_hour: p.max_tool_calls_per_hour,
            max_usd_per_day_cents: p.max_usd_per_day_cents.clone(),
            max_memory_bytes: p.max_memory_bytes,
        }
    }
}

// -----------------------------------------------------------------------------
// Passport
// -----------------------------------------------------------------------------

impl TryFrom<&proto::Passport> for Passport {
    type Error = PassportError;

    /// Decode a `proto::Passport` into the ergonomic [`Passport`].
    ///
    /// This does NOT verify the self-signature; the caller is responsible
    /// for calling [`Passport::verify_self_signature`] (or pushing through
    /// the registry, which does that as part of admission).
    ///
    /// The `extensions` field is dropped on decode — we don't surface
    /// unrecognized extensions to the ergonomic type until an RFC promotes
    /// them.
    fn try_from(p: &proto::Passport) -> Result<Self, Self::Error> {
        let spec_version = SpecVersion::try_from(
            p.spec_version
                .as_ref()
                .ok_or_else(|| missing("spec_version"))?,
        )?;
        let agent_id = AgentId::try_from(p.agent_id.as_ref().ok_or_else(|| missing("agent_id"))?)?;
        let swarm_id = SwarmId::try_from(p.swarm_id.as_ref().ok_or_else(|| missing("swarm_id"))?)?;
        let agent_public_key = PublicKey::try_from(
            p.agent_public_key
                .as_ref()
                .ok_or_else(|| missing("agent_public_key"))?,
        )?;
        let issued_at =
            Timestamp::try_from(p.issued_at.as_ref().ok_or_else(|| missing("issued_at"))?)?;
        let expires_at = p.expires_at.as_ref().map(Timestamp::try_from).transpose()?;
        let resources = p
            .resources
            .as_ref()
            .map(ResourceDeclaration::from)
            .unwrap_or_default();
        let tier = PassportTier::try_from(p.tier)?;
        let capabilities = p
            .capabilities
            .iter()
            .map(CapabilityDeclaration::from)
            .collect();
        let agent_signature = p
            .agent_signature
            .as_ref()
            .map(Signature::try_from)
            .transpose()?;

        Ok(Passport {
            spec_version,
            agent_id,
            swarm_id,
            agent_public_key,
            owner: p.owner.clone(),
            framework: p.framework.clone(),
            framework_version: p.framework_version.clone(),
            capabilities,
            accepted_constitution_version: p.accepted_constitution_version.clone(),
            tier,
            resources,
            issued_at,
            expires_at,
            default_model_provider: p.default_model_provider.clone(),
            default_model_name: p.default_model_name.clone(),
            agent_signature,
        })
    }
}

// -----------------------------------------------------------------------------
// RegistrationOutcome ↔ RegistrationResult
// -----------------------------------------------------------------------------

impl From<RegistrationStatus> for i32 {
    fn from(s: RegistrationStatus) -> Self {
        // prost strips the prefix that matches the enum's own type name
        // (`Status` → `STATUS_`). The proto variants use the
        // `REGISTRATION_STATUS_*` prefix which doesn't match, so prost
        // keeps the full name — the generated variants are
        // `RegistrationStatus*`. (Same pattern as SealStatus.State.)
        match s {
            RegistrationStatus::Accepted => {
                proto::registration_result::Status::RegistrationStatusAccepted as i32
            }
            RegistrationStatus::Rejected => {
                proto::registration_result::Status::RegistrationStatusRejected as i32
            }
            RegistrationStatus::PendingReview => {
                proto::registration_result::Status::RegistrationStatusPendingReview as i32
            }
        }
    }
}

impl From<&RegistrationOutcome> for proto::RegistrationResult {
    /// Encode the ergonomic outcome for the wire. The `registration_receipt`
    /// is set when the registry produced one (any non-rejected outcome);
    /// `rejection_reason` is set when the outcome is `Rejected`.
    fn from(o: &RegistrationOutcome) -> Self {
        proto::RegistrationResult {
            status: o.status.into(),
            agent_id: Some((&o.agent_id).into()),
            registration_receipt: o.registration_receipt.as_ref().map(Into::into),
            rejection_reason: o.rejection_reason.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityDeclaration, Passport, PassportTier};
    use yutha_core::{AgentId, SpecVersion, SwarmId, Timestamp};
    use yutha_crypto::sign::generate_keypair;
    use yutha_proto::Message;

    fn signed_fixture() -> Passport {
        let key = generate_keypair();
        Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(AgentId::new())
            .swarm_id(SwarmId::new())
            .agent_public_key(key.public())
            .owner("test-owner")
            .framework("test-framework", "0.1.0")
            .declares(
                CapabilityDeclaration::of_kind("issue_refund")
                    .with_tag("finance")
                    .with_bound("usd_max", "500.00"),
            )
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&key)
            .unwrap()
    }

    #[test]
    fn passport_round_trips_to_proto() {
        let p = signed_fixture();
        let proto: proto::Passport = (&p).into();
        assert_eq!(proto.owner, "test-owner");
        assert_eq!(proto.tier, proto::PassportTier::Minimal as i32);
        assert_eq!(proto.capabilities.len(), 1);
        assert_eq!(proto.capabilities[0].kind, "issue_refund");
        assert!(proto.agent_signature.is_some());
    }

    #[test]
    fn canonical_proto_clears_signature_and_extensions() {
        let p = signed_fixture();
        let cp = p.to_canonical_proto();
        assert!(cp.agent_signature.is_none(), "signature must be cleared");
        assert!(cp.extensions.is_none(), "extensions must be cleared");
        assert_eq!(cp.owner, "test-owner", "other fields survive");
    }

    #[test]
    fn canonical_encoding_is_bytewise_deterministic() {
        let p = signed_fixture();
        let a = p.to_canonical_proto().encode_to_vec();
        let b = p.to_canonical_proto().encode_to_vec();
        let c = p.clone().to_canonical_proto().encode_to_vec();
        assert_eq!(a, b, "repeated encoding within same Passport");
        assert_eq!(a, c, "clones encode identically");
    }

    #[test]
    fn passport_tier_maps_to_wire_integers() {
        // Should match the existing `to_wire()` mapping in tier.rs.
        for (tier, expected) in [
            (PassportTier::Minimal, 1),
            (PassportTier::Standard, 2),
            (PassportTier::Verifiable, 3),
        ] {
            assert_eq!(<PassportTier as Into<i32>>::into(tier), expected);
        }
    }

    // -------------------------------------------------------------------------
    // Reverse conversion tests (proto → ergonomic)
    // -------------------------------------------------------------------------

    #[test]
    fn passport_round_trips_proto_to_ergonomic() {
        let original = signed_fixture();
        let p: proto::Passport = (&original).into();
        let back = Passport::try_from(&p).expect("reverse conversion succeeds");

        assert_eq!(back.agent_id, original.agent_id);
        assert_eq!(back.swarm_id, original.swarm_id);
        assert_eq!(back.owner, original.owner);
        assert_eq!(back.framework, original.framework);
        assert_eq!(back.capabilities.len(), original.capabilities.len());
        assert_eq!(back.capabilities[0].kind, original.capabilities[0].kind);
        assert_eq!(back.tier, original.tier);

        // The reverse-decoded passport must still verify its self-signature
        // — i.e. canonical bytes are preserved through the round trip.
        back.verify_self_signature()
            .expect("reverse-decoded passport must verify");
    }

    #[test]
    fn passport_missing_agent_id_rejected() {
        let p = signed_fixture();
        let mut wire: proto::Passport = (&p).into();
        wire.agent_id = None;
        let err = Passport::try_from(&wire).unwrap_err();
        assert!(matches!(err, PassportError::Core(_)), "got: {err:?}");
        assert!(err.to_string().contains("agent_id"), "got: {err}");
    }

    #[test]
    fn passport_tier_unknown_rejected() {
        let err = PassportTier::try_from(proto::PassportTier::Unknown as i32).unwrap_err();
        assert!(matches!(err, PassportError::Core(_)));
    }

    #[test]
    fn passport_tier_out_of_range_rejected() {
        let err = PassportTier::try_from(99).unwrap_err();
        assert!(matches!(err, PassportError::Core(_)));
    }

    #[test]
    fn registration_outcome_encodes_to_proto() {
        let outcome = RegistrationOutcome {
            status: RegistrationStatus::Accepted,
            agent_id: AgentId::new(),
            registration_receipt: Some(
                yutha_core::Hash::new(yutha_core::HashAlgorithm::Sha256, vec![1u8; 32]).unwrap(),
            ),
            rejection_reason: String::new(),
        };
        let p: proto::RegistrationResult = (&outcome).into();
        assert_eq!(
            p.status,
            proto::registration_result::Status::RegistrationStatusAccepted as i32
        );
        assert!(p.registration_receipt.is_some());
        assert!(p.rejection_reason.is_empty());
    }

    #[test]
    fn registration_status_maps_to_wire_integers() {
        // Wire integers: ACCEPTED=1, REJECTED=2, PENDING_REVIEW=3. These
        // are normative per the proto enum and must not drift.
        assert_eq!(
            <RegistrationStatus as Into<i32>>::into(RegistrationStatus::Accepted),
            1
        );
        assert_eq!(
            <RegistrationStatus as Into<i32>>::into(RegistrationStatus::Rejected),
            2
        );
        assert_eq!(
            <RegistrationStatus as Into<i32>>::into(RegistrationStatus::PendingReview),
            3
        );
    }
}
