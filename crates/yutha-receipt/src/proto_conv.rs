//! Conversions between ergonomic [`yutha-receipt`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! The forward direction (ergonomic → proto) is used in two hot paths:
//!
//! 1. **Content addressing.** [`Receipt::canonical_bytes`](crate::Receipt)
//!    encodes a proto representation with all signatures cleared and the
//!    seal field normalized; the resulting bytes hash to the receipt id.
//! 2. **Signing.** The same canonical bytes are what the actor (and any
//!    countersigners) sign.
//!
//! The reverse direction (proto → ergonomic) is used by the control-plane
//! gRPC handlers: requests arrive as proto, and the handlers decode them into
//! ergonomic types before calling the [`ReceiptStore`](crate::ReceiptStore).
//! Reverse conversions are fallible (`TryFrom`) because the wire shape carries
//! `Option<T>` for nested messages and unknown enum variants that the
//! ergonomic types reject up front.
//!
//! ## Determinism
//!
//! Wire-equivalence across languages requires that two implementations of the
//! spec produce *bytewise-identical* encodings of the same logical receipt.
//! prost-build is configured (in `yutha-proto`'s `build.rs`) with
//! `btree_map(["."])` so map fields encode with sorted keys; combined with
//! prost's tag-sorted field encoding and our explicit zeroing of seal/signature
//! state during canonicalization, this gives a deterministic canonical form.

use crate::{
    query::{ActionKindQuery, AgentQuery, PredecessorQuery, Query, TimeRangeQuery},
    Evidence, Receipt, ReceiptError, SealState, SealStatus, SignatureRole, SignedBy,
};
use yutha_core::{
    AgentId, CausalRef, CostAnnotation, Hash, Signature, SpecVersion, SwarmId, Timestamp,
};
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
        // `on_chain_tx_digest` + `swarm_anchor_object_id` map to the raw
        // bytes form expected by the proto (RFC 0014). `None` → empty
        // Vec, which prost serializes as a zero-length field and the
        // canonical-bytes form omits entirely.
        proto::SealStatus {
            state: s.state.into(),
            batch_root: s.batch_root.as_ref().map(Into::into),
            merkle_path: s.merkle_path.iter().map(Into::into).collect(),
            sealed_at: s.sealed_at.as_ref().map(Into::into),
            on_chain_tx_digest: s.on_chain_tx_digest.clone().unwrap_or_default(),
            swarm_anchor_object_id: s.swarm_anchor_object_id.clone().unwrap_or_default(),
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

// =============================================================================
// REVERSE: proto → ergonomic
// =============================================================================
//
// All reverse conversions are fallible because:
// - proto3 makes every nested message Option<T>; required fields must be
//   present.
// - Unknown enum values (e.g. SIGNATURE_ROLE_UNKNOWN) are rejected: a peer
//   that doesn't understand a role should not silently coerce to one we do.
// - yutha-core's typed wrappers (AgentId, Hash, Signature, …) enforce their
//   own validation on bytes.

/// Helper: turn a required-but-missing proto field into a structured error.
///
/// Returns a [`CoreError::Validation`] wrapped through `ReceiptError::Core`
/// (the `#[from]` impl handles the wrap). Both map to `INVALID_ARGUMENT`
/// when surfaced via the gRPC error layer, and the message is the same
/// shape regardless of whether the conversion was for a Receipt, a Query,
/// or any nested message.
fn missing(field: &'static str) -> ReceiptError {
    ReceiptError::Core(yutha_core::CoreError::validation(format!(
        "required field missing: {field}"
    )))
}

// -----------------------------------------------------------------------------
// SignatureRole
// -----------------------------------------------------------------------------

impl TryFrom<i32> for SignatureRole {
    type Error = ReceiptError;

    /// Map a wire i32 to the ergonomic enum. Rejects UNKNOWN (0) and any
    /// out-of-range value the spec hasn't allocated. Receipts whose role
    /// we can't interpret are signature-failures from this layer's POV.
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        // Match on the proto enum's i32 constants rather than re-deriving
        // numbers; if the .proto changes wire numbers, this catches it.
        match proto::SignatureRole::try_from(v).map_err(|_| ReceiptError::SignatureFailed {
            detail: format!("unknown signature role: {v}"),
        })? {
            proto::SignatureRole::Unknown => Err(ReceiptError::SignatureFailed {
                detail: "signature role unset (UNKNOWN)".into(),
            }),
            proto::SignatureRole::Actor => Ok(SignatureRole::Actor),
            proto::SignatureRole::ControlPlane => Ok(SignatureRole::ControlPlane),
            proto::SignatureRole::Supervisor => Ok(SignatureRole::Supervisor),
            proto::SignatureRole::Attestation => Ok(SignatureRole::Attestation),
            proto::SignatureRole::BatchRoot => Ok(SignatureRole::BatchRoot),
        }
    }
}

// -----------------------------------------------------------------------------
// SignedBy
// -----------------------------------------------------------------------------

impl TryFrom<&proto::SignedBy> for SignedBy {
    type Error = ReceiptError;

    fn try_from(p: &proto::SignedBy) -> Result<Self, Self::Error> {
        let role = SignatureRole::try_from(p.role)?;
        let signature =
            Signature::try_from(p.signature.as_ref().ok_or_else(|| missing("signature"))?)?;
        let signed_at =
            Timestamp::try_from(p.signed_at.as_ref().ok_or_else(|| missing("signed_at"))?)?;
        Ok(SignedBy {
            role,
            signature,
            signed_at,
        })
    }
}

// -----------------------------------------------------------------------------
// Evidence
// -----------------------------------------------------------------------------

impl From<&proto::Evidence> for Evidence {
    /// Evidence has no required nested messages or enums — every field is a
    /// plain scalar. So `From` (infallible) is fine here.
    fn from(p: &proto::Evidence) -> Self {
        Evidence {
            key: p.key.clone(),
            type_url: p.type_url.clone(),
            value: p.value.clone(),
            sensitive: p.sensitive,
        }
    }
}

// -----------------------------------------------------------------------------
// SealStatus
// -----------------------------------------------------------------------------

impl TryFrom<i32> for SealState {
    type Error = ReceiptError;

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match proto::seal_status::State::try_from(v)
            .map_err(|_| ReceiptError::InvalidQuery(format!("unknown seal state: {v}")))?
        {
            proto::seal_status::State::SealStateUnknown => {
                // Default-zero on the wire — treat as unsealed for backward
                // compatibility with producers that don't set the field.
                Ok(SealState::Unsealed)
            }
            proto::seal_status::State::SealStateUnsealed => Ok(SealState::Unsealed),
            proto::seal_status::State::SealStateSealed => Ok(SealState::Sealed),
        }
    }
}

impl TryFrom<&proto::SealStatus> for SealStatus {
    type Error = ReceiptError;

    fn try_from(p: &proto::SealStatus) -> Result<Self, Self::Error> {
        let state = SealState::try_from(p.state)?;
        let batch_root = p.batch_root.as_ref().map(Hash::try_from).transpose()?;
        let merkle_path = p
            .merkle_path
            .iter()
            .map(Hash::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let sealed_at = p.sealed_at.as_ref().map(Timestamp::try_from).transpose()?;
        // Empty Vec → None (the proto-default representation for unset
        // bytes fields). RFC 0014: present together iff SuiSealer set
        // them; LocalSealer leaves both empty.
        let on_chain_tx_digest = if p.on_chain_tx_digest.is_empty() {
            None
        } else {
            Some(p.on_chain_tx_digest.clone())
        };
        let swarm_anchor_object_id = if p.swarm_anchor_object_id.is_empty() {
            None
        } else {
            Some(p.swarm_anchor_object_id.clone())
        };
        Ok(SealStatus {
            state,
            batch_root,
            merkle_path,
            sealed_at,
            on_chain_tx_digest,
            swarm_anchor_object_id,
        })
    }
}

// -----------------------------------------------------------------------------
// Receipt
// -----------------------------------------------------------------------------

impl TryFrom<&proto::Receipt> for Receipt {
    type Error = ReceiptError;

    fn try_from(p: &proto::Receipt) -> Result<Self, Self::Error> {
        let spec_version = SpecVersion::try_from(
            p.spec_version
                .as_ref()
                .ok_or_else(|| missing("spec_version"))?,
        )?;
        let swarm_id = SwarmId::try_from(p.swarm_id.as_ref().ok_or_else(|| missing("swarm_id"))?)?;
        let actor = AgentId::try_from(p.actor.as_ref().ok_or_else(|| missing("actor"))?)?;
        // `causal` is a message in the proto; ergonomic CausalRef defaults to
        // empty when not present (e.g. genesis receipts).
        let causal = p
            .causal
            .as_ref()
            .map(CausalRef::try_from)
            .transpose()?
            .unwrap_or_default();
        let evidence = p.evidence.iter().map(Evidence::from).collect();
        let cost = p.cost.as_ref().map(CostAnnotation::try_from).transpose()?;
        let occurred_at = Timestamp::try_from(
            p.occurred_at
                .as_ref()
                .ok_or_else(|| missing("occurred_at"))?,
        )?;
        let seal = p
            .seal
            .as_ref()
            .map(SealStatus::try_from)
            .transpose()?
            .unwrap_or_default();
        let signatures = p
            .signatures
            .iter()
            .map(SignedBy::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Receipt {
            spec_version,
            swarm_id,
            actor,
            action_kind: p.action_kind.clone(),
            causal,
            evidence,
            constitution_version: p.constitution_version.clone(),
            cost,
            occurred_at,
            seal,
            signatures,
        })
    }
}

// -----------------------------------------------------------------------------
// Query
// -----------------------------------------------------------------------------

impl TryFrom<&proto::PredecessorQuery> for PredecessorQuery {
    type Error = ReceiptError;
    fn try_from(p: &proto::PredecessorQuery) -> Result<Self, Self::Error> {
        Ok(PredecessorQuery {
            predecessor: Hash::try_from(
                p.predecessor
                    .as_ref()
                    .ok_or_else(|| missing("predecessor"))?,
            )?,
        })
    }
}

impl TryFrom<&proto::AgentQuery> for AgentQuery {
    type Error = ReceiptError;
    fn try_from(p: &proto::AgentQuery) -> Result<Self, Self::Error> {
        Ok(AgentQuery {
            agent_id: AgentId::try_from(p.agent_id.as_ref().ok_or_else(|| missing("agent_id"))?)?,
        })
    }
}

impl TryFrom<&proto::ActionKindQuery> for ActionKindQuery {
    type Error = ReceiptError;
    fn try_from(p: &proto::ActionKindQuery) -> Result<Self, Self::Error> {
        Ok(ActionKindQuery {
            action_kind: p.action_kind.clone(),
        })
    }
}

impl TryFrom<&proto::TimeRangeQuery> for TimeRangeQuery {
    type Error = ReceiptError;
    fn try_from(p: &proto::TimeRangeQuery) -> Result<Self, Self::Error> {
        Ok(TimeRangeQuery {
            from: Timestamp::try_from(p.from.as_ref().ok_or_else(|| missing("from"))?)?,
            to: Timestamp::try_from(p.to.as_ref().ok_or_else(|| missing("to"))?)?,
        })
    }
}

impl TryFrom<&proto::QueryRequest> for Query {
    type Error = ReceiptError;

    /// Decode the `oneof by` selector into the ergonomic [`Query`] enum.
    /// Returns `InvalidQuery` if the selector is empty (the client sent a
    /// `QueryRequest` with no variant set).
    ///
    /// Note that `limit` and `page_token` on the proto are *not* part of
    /// [`Query`]; the caller threads them through separately so the trait
    /// signature stays focused on "what to look up" vs. "how to paginate".
    fn try_from(p: &proto::QueryRequest) -> Result<Self, Self::Error> {
        use proto::query_request::By;
        let by =
            p.by.as_ref()
                .ok_or_else(|| ReceiptError::InvalidQuery("query selector not set".into()))?;
        match by {
            By::ByReceiptId(h) => Ok(Query::ByReceiptId(Hash::try_from(h)?)),
            By::ByPredecessor(q) => Ok(Query::ByPredecessor(PredecessorQuery::try_from(q)?)),
            By::ByAgent(q) => Ok(Query::ByAgent(AgentQuery::try_from(q)?)),
            By::ByActionKind(q) => Ok(Query::ByActionKind(ActionKindQuery::try_from(q)?)),
            By::ByTime(q) => Ok(Query::ByTimeRange(TimeRangeQuery::try_from(q)?)),
        }
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

    // -------------------------------------------------------------------------
    // Reverse conversion tests (proto → ergonomic)
    // -------------------------------------------------------------------------

    #[test]
    fn signature_role_reverse_known_values() {
        assert_eq!(
            SignatureRole::try_from(proto::SignatureRole::Actor as i32).unwrap(),
            SignatureRole::Actor
        );
        assert_eq!(
            SignatureRole::try_from(proto::SignatureRole::BatchRoot as i32).unwrap(),
            SignatureRole::BatchRoot
        );
    }

    #[test]
    fn signature_role_reverse_unknown_rejected() {
        // Wire value 0 (UNKNOWN) must not silently coerce to Actor.
        let r = SignatureRole::try_from(proto::SignatureRole::Unknown as i32);
        assert!(matches!(r, Err(ReceiptError::SignatureFailed { .. })));
    }

    #[test]
    fn signature_role_reverse_out_of_range_rejected() {
        // A value beyond the spec'd allocation — peer ahead of us. We
        // surface, never silently coerce.
        let r = SignatureRole::try_from(99);
        assert!(matches!(r, Err(ReceiptError::SignatureFailed { .. })));
    }

    #[test]
    fn receipt_round_trips_proto_to_ergonomic() {
        let original = fixture();
        // Need a signature so reverse-converting exercises that path too.
        let mut original = original;
        original.signatures.push(SignedBy::new(
            SignatureRole::Actor,
            Signature::new(SignatureAlgorithm::Ed25519, vec![0u8; 64], vec![0u8; 32]).unwrap(),
            Timestamp::now(),
        ));

        let p: proto::Receipt = (&original).into();
        let back = Receipt::try_from(&p).expect("reverse conversion should succeed");

        // Spot-check the round-trip — full equality is intentionally not used
        // because Timestamp's wall_clock field is a SystemTime conversion that
        // can lose ns precision through proto's i64 nanos representation.
        assert_eq!(back.action_kind, original.action_kind);
        assert_eq!(back.constitution_version, original.constitution_version);
        assert_eq!(back.actor, original.actor);
        assert_eq!(back.swarm_id, original.swarm_id);
        assert_eq!(back.evidence.len(), original.evidence.len());
        assert_eq!(back.evidence[0].key, original.evidence[0].key);
        assert_eq!(back.signatures.len(), 1);
        assert_eq!(back.signatures[0].role, SignatureRole::Actor);
    }

    #[test]
    fn receipt_missing_actor_rejected() {
        let r = fixture();
        let mut p: proto::Receipt = (&r).into();
        p.actor = None;
        let err = Receipt::try_from(&p).unwrap_err();
        // Missing-required-field is reported as a CoreError::Validation
        // wrapped in ReceiptError::Core; both surface as INVALID_ARGUMENT
        // at the gRPC boundary.
        assert!(matches!(err, ReceiptError::Core(_)), "got: {err:?}");
        assert!(err.to_string().contains("actor"), "got: {err}");
    }

    #[test]
    fn seal_state_unknown_maps_to_unsealed() {
        // Wire-default 0 must not block round-tripping receipts where the
        // producer never set seal state; treat as Unsealed.
        let s = SealState::try_from(proto::seal_status::State::SealStateUnknown as i32).unwrap();
        assert_eq!(s, SealState::Unsealed);
    }

    #[test]
    fn seal_state_out_of_range_rejected() {
        let r = SealState::try_from(99);
        assert!(matches!(r, Err(ReceiptError::InvalidQuery(_))));
    }

    #[test]
    fn query_request_by_receipt_id_decodes() {
        use yutha_core::HashAlgorithm;
        let h = yutha_core::Hash::new(HashAlgorithm::Sha256, vec![0xab; 32]).unwrap();
        let p = proto::QueryRequest {
            by: Some(proto::query_request::By::ByReceiptId((&h).into())),
            limit: 0,
            page_token: vec![],
        };
        let q = Query::try_from(&p).unwrap();
        match q {
            Query::ByReceiptId(decoded) => assert_eq!(decoded, h),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn query_request_by_action_kind_decodes() {
        let p = proto::QueryRequest {
            by: Some(proto::query_request::By::ByActionKind(
                proto::ActionKindQuery {
                    action_kind: "envelope.send".into(),
                },
            )),
            limit: 0,
            page_token: vec![],
        };
        let q = Query::try_from(&p).unwrap();
        match q {
            Query::ByActionKind(akq) => assert_eq!(akq.action_kind, "envelope.send"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn query_request_empty_selector_rejected() {
        let p = proto::QueryRequest {
            by: None,
            limit: 0,
            page_token: vec![],
        };
        let r = Query::try_from(&p);
        assert!(matches!(r, Err(ReceiptError::InvalidQuery(_))));
    }

    #[test]
    fn evidence_round_trips() {
        let e = Evidence::sensitive("input_payload", "type.yutha.dev/v1/Bytes", vec![1, 2, 3]);
        let p: proto::Evidence = (&e).into();
        let back: Evidence = (&p).into();
        assert_eq!(back.key, e.key);
        assert_eq!(back.type_url, e.type_url);
        assert_eq!(back.value, e.value);
        assert_eq!(back.sensitive, e.sensitive);
    }
}
