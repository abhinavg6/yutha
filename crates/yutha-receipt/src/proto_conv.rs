//! Conversions between ergonomic [`yutha-receipt`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! These conversions are deliberately one-way (ergonomic → proto). The proto
//! types are used for two things and two things only:
//!
//! 1. **Content addressing.** [`Receipt::canonical_bytes`](crate::Receipt)
//!    encodes a proto representation with all signatures cleared and the
//!    seal field normalized; the resulting bytes hash to the receipt id.
//! 2. **Signing.** The same canonical bytes are what the actor (and any
//!    countersigners) sign.
//!
//! We do not currently decode proto → ergonomic types in any hot path; if a
//! use case emerges, those conversions will live here too.
//!
//! ## Determinism
//!
//! Wire-equivalence across languages requires that two implementations of the
//! spec produce *bytewise-identical* encodings of the same logical receipt.
//! prost-build is configured (in `yutha-proto`'s `build.rs`) with
//! `btree_map(["."])` so map fields encode with sorted keys; combined with
//! prost's tag-sorted field encoding and our explicit zeroing of seal/signature
//! state during canonicalization, this gives a deterministic canonical form.

use crate::{Evidence, Receipt, SealState, SealStatus, SignatureRole, SignedBy};
use yutha_proto::receipt::v1 as proto;

// -----------------------------------------------------------------------------
// SignatureRole
// -----------------------------------------------------------------------------

impl From<SignatureRole> for i32 {
    fn from(role: SignatureRole) -> Self {
        match role {
            SignatureRole::Actor => proto::SignatureRole::Actor as i32,
            SignatureRole::ControlPlane => proto::SignatureRole::ControlPlane as i32,
            SignatureRole::Supervisor => proto::SignatureRole::Supervisor as i32,
            SignatureRole::Attestation => proto::SignatureRole::Attestation as i32,
            SignatureRole::BatchRoot => proto::SignatureRole::BatchRoot as i32,
        }
    }
}

// -----------------------------------------------------------------------------
// SignedBy
// -----------------------------------------------------------------------------

impl From<&SignedBy> for proto::SignedBy {
    fn from(s: &SignedBy) -> Self {
        proto::SignedBy {
            role: s.role.into(),
            signature: Some((&s.signature).into()),
            signed_at: Some((&s.signed_at).into()),
        }
    }
}

// -----------------------------------------------------------------------------
// Evidence
// -----------------------------------------------------------------------------

impl From<&Evidence> for proto::Evidence {
    fn from(e: &Evidence) -> Self {
        proto::Evidence {
            key: e.key.clone(),
            type_url: e.type_url.clone(),
            value: e.value.clone(),
            sensitive: e.sensitive,
        }
    }
}

// -----------------------------------------------------------------------------
// SealStatus
// -----------------------------------------------------------------------------

impl From<SealState> for i32 {
    fn from(s: SealState) -> Self {
        // prost strips a prefix derived from the enum *type* name (`State`
        // → `STATE_`). Our variants use the proto-style `SEAL_STATE_*`
        // prefix, which doesn't match, so prost keeps the full name and the
        // generated variants are `SealStateUnsealed` / `SealStateSealed`.
        // (The variant *numbers* are normative; the Rust identifiers are
        // not.)
        match s {
            SealState::Unsealed => proto::seal_status::State::SealStateUnsealed as i32,
            SealState::Sealed => proto::seal_status::State::SealStateSealed as i32,
        }
    }
}

impl From<&SealStatus> for proto::SealStatus {
    fn from(s: &SealStatus) -> Self {
        proto::SealStatus {
            state: s.state.into(),
            batch_root: s.batch_root.as_ref().map(Into::into),
            merkle_path: s.merkle_path.iter().map(Into::into).collect(),
            sealed_at: s.sealed_at.as_ref().map(Into::into),
        }
    }
}

// -----------------------------------------------------------------------------
// Receipt
// -----------------------------------------------------------------------------

impl From<&Receipt> for proto::Receipt {
    /// Convert an ergonomic [`Receipt`] into its prost-generated wire form.
    ///
    /// The resulting proto value carries every field of the receipt, including
    /// signatures and seal state. For content-addressing,
    /// [`Receipt::canonical_bytes`] uses [`Receipt::to_canonical_proto`] which
    /// clears those fields first.
    fn from(r: &Receipt) -> Self {
        proto::Receipt {
            spec_version: Some((&r.spec_version).into()),
            swarm_id: Some((&r.swarm_id).into()),
            actor: Some((&r.actor).into()),
            action_kind: r.action_kind.clone(),
            causal: Some((&r.causal).into()),
            evidence: r.evidence.iter().map(Into::into).collect(),
            constitution_version: r.constitution_version.clone(),
            cost: r.cost.as_ref().map(Into::into),
            occurred_at: Some((&r.occurred_at).into()),
            seal: Some((&r.seal).into()),
            extensions: None,
            signatures: r.signatures.iter().map(Into::into).collect(),
        }
    }
}

impl Receipt {
    /// Produce the canonical proto representation used for content-addressing.
    ///
    /// This is the receipt with:
    ///
    /// - `signatures` cleared — content-addressing must be stable regardless
    ///   of who signs, and signatures sign over the canonical bytes (so they
    ///   must not be present when those bytes are computed).
    /// - `seal` normalized to the proto default — the receipt store assigns
    ///   seal status *after* the receipt is admitted; the receipt id must be
    ///   stable from the producer's first emission through eventual sealing.
    /// - `extensions` left as None for v1.0 (we don't yet allow vendor
    ///   extensions to participate in content-addressing; an RFC can lift
    ///   this if/when extensions stabilize).
    ///
    /// Returned as the prost-generated type so callers can either
    /// `.encode_to_vec()` directly or inspect the structure for tests.
    pub fn to_canonical_proto(&self) -> proto::Receipt {
        let mut p: proto::Receipt = self.into();
        p.signatures.clear();
        p.seal = None;
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
    use crate::{Evidence, Receipt, SignatureRole, SignedBy};
    use yutha_core::{AgentId, Signature, SignatureAlgorithm, SpecVersion, SwarmId, Timestamp};
    use yutha_proto::Message;

    fn fixture() -> Receipt {
        Receipt::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::new())
            .actor(AgentId::new())
            .action_kind("envelope.send")
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::now())
            .evidence(Evidence::new(
                "envelope_hash",
                "type.yutha.dev/v1/Hash",
                vec![0xab; 32],
            ))
            .build()
            .unwrap()
    }

    #[test]
    fn receipt_round_trips_to_proto() {
        let r = fixture();
        let p: proto::Receipt = (&r).into();

        assert_eq!(p.action_kind, "envelope.send");
        assert_eq!(p.constitution_version, "1.0.0");
        assert_eq!(p.evidence.len(), 1);
        assert_eq!(p.evidence[0].key, "envelope_hash");

        // Identifiers carry their byte representation through.
        assert_eq!(p.actor.as_ref().unwrap().value, r.actor.as_bytes().to_vec());
        assert_eq!(
            p.swarm_id.as_ref().unwrap().value,
            r.swarm_id.as_bytes().to_vec()
        );
    }

    #[test]
    fn canonical_proto_clears_signatures_and_seal() {
        let mut r = fixture();
        r.signatures.push(SignedBy::new(
            SignatureRole::Actor,
            Signature::new(SignatureAlgorithm::Ed25519, vec![0u8; 64], vec![0u8; 32]).unwrap(),
            Timestamp::now(),
        ));

        let p = r.to_canonical_proto();
        assert!(p.signatures.is_empty(), "signatures must be cleared");
        assert!(p.seal.is_none(), "seal must be cleared");
        assert!(p.extensions.is_none(), "extensions must be cleared");

        // Other fields survive.
        assert_eq!(p.action_kind, "envelope.send");
    }

    #[test]
    fn canonical_encoding_is_deterministic_within_run() {
        let r = fixture();
        let a = r.to_canonical_proto().encode_to_vec();
        let b = r.to_canonical_proto().encode_to_vec();
        assert_eq!(a, b, "canonical encoding must be deterministic");
    }

    #[test]
    fn signature_role_round_trips_through_i32() {
        let cases = [
            (SignatureRole::Actor, proto::SignatureRole::Actor as i32),
            (
                SignatureRole::ControlPlane,
                proto::SignatureRole::ControlPlane as i32,
            ),
            (
                SignatureRole::Supervisor,
                proto::SignatureRole::Supervisor as i32,
            ),
            (
                SignatureRole::Attestation,
                proto::SignatureRole::Attestation as i32,
            ),
            (
                SignatureRole::BatchRoot,
                proto::SignatureRole::BatchRoot as i32,
            ),
        ];
        for (role, expected) in cases {
            let got: i32 = role.into();
            assert_eq!(got, expected);
        }
    }
}
