//! Conversions between ergonomic [`yutha-passport`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! Same pattern as `yutha-receipt::proto_conv`: ergonomic → proto, one way.
//! Used for content-addressing and signature verification through
//! [`Passport::to_canonical_proto`].

use crate::{CapabilityDeclaration, Passport, PassportTier, ResourceDeclaration};
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
}
