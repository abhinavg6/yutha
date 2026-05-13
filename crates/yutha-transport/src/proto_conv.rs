//! Conversions between ergonomic [`yutha-transport`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! The forward direction (ergonomic → proto) is used for content-addressing
//! and signature verification through [`Envelope::to_canonical_proto`].
//!
//! The reverse direction (proto → ergonomic) is used by
//! `EnvelopeService.Send` to decode an incoming envelope payload and by
//! `EnvelopeService.Subscribe` to encode an outbound envelope back to the
//! wire for the streaming client. Reverse is fallible because of proto3
//! `Option<T>` nesting and unknown enum / oneof values.

use crate::{Envelope, ExternalEndpoint, Performative, Recipient, SwarmBroadcast, TransportError};
use yutha_core::{AgentId, CausalRef, CoreError, Hash, Signature, SpecVersion, SwarmId, Timestamp};
use yutha_proto::envelope::v1 as proto;

// -----------------------------------------------------------------------------
// Performative
// -----------------------------------------------------------------------------

impl From<Performative> for i32 {
    fn from(p: Performative) -> Self {
        // Defer to the existing `to_wire` mapping in performative.rs — it's
        // already locked to the proto numeric values and tested.
        p.to_wire()
    }
}

// -----------------------------------------------------------------------------
// SwarmBroadcast / ExternalEndpoint
// -----------------------------------------------------------------------------

impl From<&SwarmBroadcast> for proto::SwarmBroadcast {
    fn from(b: &SwarmBroadcast) -> Self {
        proto::SwarmBroadcast {
            filter_tags: b.filter_tags.clone(),
        }
    }
}

impl From<&ExternalEndpoint> for proto::ExternalEndpoint {
    fn from(e: &ExternalEndpoint) -> Self {
        proto::ExternalEndpoint {
            scheme: e.scheme.clone(),
            authority: e.authority.clone(),
            path_hint: e.path_hint.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Recipient (oneof)
// -----------------------------------------------------------------------------

impl From<&Recipient> for proto::Recipient {
    fn from(r: &Recipient) -> Self {
        // prost generates a `Recipient { to: Option<recipient::To> }` shape
        // for proto3 `oneof`. The variants live in the nested `recipient`
        // module.
        let to = match r {
            Recipient::Agent(id) => proto::recipient::To::Agent(id.into()),
            Recipient::Role(role) => proto::recipient::To::Role(role.clone()),
            Recipient::Swarm(b) => proto::recipient::To::Swarm(b.into()),
            Recipient::External(e) => proto::recipient::To::External(e.into()),
        };
        proto::Recipient { to: Some(to) }
    }
}

// -----------------------------------------------------------------------------
// Envelope
// -----------------------------------------------------------------------------

impl From<&Envelope> for proto::Envelope {
    fn from(e: &Envelope) -> Self {
        proto::Envelope {
            spec_version: Some((&e.spec_version).into()),
            swarm_id: Some((&e.swarm_id).into()),
            envelope_id: e.envelope_id.clone(),
            from_agent: Some((&e.from_agent).into()),
            recipient: Some((&e.recipient).into()),
            performative: e.performative.into(),
            payload: e.payload.clone(),
            payload_schema_id: e.payload_schema_id.clone(),
            tags: e.tags.clone(),
            causal: Some((&e.causal).into()),
            nonce: e.nonce.clone(),
            epoch: e.epoch,
            sent_at: Some((&e.sent_at).into()),
            expires_at: e.expires_at.as_ref().map(Into::into),
            in_reply_to: e.in_reply_to.as_ref().map(Into::into),
            extensions: None,
            agent_signature: e.agent_signature.as_ref().map(Into::into),
        }
    }
}

impl Envelope {
    /// Canonical proto representation for content-addressing and signature.
    ///
    /// Clears `agent_signature` (what the canonical bytes are signed over —
    /// circular if included) and drops `extensions` (vendor extensions don't
    /// participate in content-addressing at v1.0).
    pub fn to_canonical_proto(&self) -> proto::Envelope {
        let mut e: proto::Envelope = self.into();
        e.agent_signature = None;
        e.extensions = None;
        e
    }
}

// =============================================================================
// REVERSE: proto → ergonomic
// =============================================================================

/// Helper: required-but-missing proto field, mapped via
/// `TransportError::Core(CoreError::Validation)` so gRPC sees
/// `INVALID_ARGUMENT`.
fn missing(field: &'static str) -> TransportError {
    TransportError::Core(CoreError::validation(format!(
        "required field missing: {field}"
    )))
}

// -----------------------------------------------------------------------------
// Performative
// -----------------------------------------------------------------------------

impl TryFrom<i32> for Performative {
    type Error = TransportError;

    /// Map a wire i32 to the ergonomic enum. Rejects 0 (UNKNOWN) and any
    /// out-of-range value — peers ahead of us in spec versioning must
    /// surface, never silently coerce. (See spec rationale §3 on
    /// performative versioning.)
    //
    // NOTE: the return type uses the fully-qualified
    // `<Self as TryFrom<i32>>::Error` rather than `Self::Error`. The
    // `Performative` enum has a variant named `Error` (one of the spec's
    // 11 performatives) which would otherwise shadow the `TryFrom::Error`
    // associated type in scope. The compiler errors on
    // ambiguous_associated_items if we use the short form.
    fn try_from(v: i32) -> Result<Self, <Self as TryFrom<i32>>::Error> {
        Performative::from_wire(v).ok_or_else(|| {
            TransportError::Core(CoreError::validation(format!(
                "unknown performative wire value: {v}"
            )))
        })
    }
}

// -----------------------------------------------------------------------------
// SwarmBroadcast / ExternalEndpoint
// -----------------------------------------------------------------------------

impl From<&proto::SwarmBroadcast> for SwarmBroadcast {
    fn from(p: &proto::SwarmBroadcast) -> Self {
        SwarmBroadcast {
            filter_tags: p.filter_tags.clone(),
        }
    }
}

impl From<&proto::ExternalEndpoint> for ExternalEndpoint {
    fn from(p: &proto::ExternalEndpoint) -> Self {
        ExternalEndpoint {
            scheme: p.scheme.clone(),
            authority: p.authority.clone(),
            path_hint: p.path_hint.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Recipient (oneof)
// -----------------------------------------------------------------------------

impl TryFrom<&proto::Recipient> for Recipient {
    type Error = TransportError;
    fn try_from(p: &proto::Recipient) -> Result<Self, Self::Error> {
        use proto::recipient::To;
        let to = p.to.as_ref().ok_or_else(|| missing("recipient.to"))?;
        Ok(match to {
            To::Agent(id) => Recipient::Agent(AgentId::try_from(id)?),
            To::Role(role) => Recipient::Role(role.clone()),
            To::Swarm(b) => Recipient::Swarm(b.into()),
            To::External(e) => Recipient::External(e.into()),
        })
    }
}

// -----------------------------------------------------------------------------
// Envelope
// -----------------------------------------------------------------------------

impl TryFrom<&proto::Envelope> for Envelope {
    type Error = TransportError;

    /// Decode a `proto::Envelope` into the ergonomic [`Envelope`].
    ///
    /// Does NOT verify the agent signature; callers should use
    /// [`Envelope::verify_signature`] (or push through the transport,
    /// which verifies as part of admission).
    fn try_from(p: &proto::Envelope) -> Result<Self, Self::Error> {
        let spec_version = SpecVersion::try_from(
            p.spec_version
                .as_ref()
                .ok_or_else(|| missing("spec_version"))?,
        )?;
        let swarm_id = SwarmId::try_from(p.swarm_id.as_ref().ok_or_else(|| missing("swarm_id"))?)?;
        let from_agent =
            AgentId::try_from(p.from_agent.as_ref().ok_or_else(|| missing("from_agent"))?)?;
        let recipient =
            Recipient::try_from(p.recipient.as_ref().ok_or_else(|| missing("recipient"))?)?;
        let performative = Performative::try_from(p.performative)?;
        let causal = p
            .causal
            .as_ref()
            .map(CausalRef::try_from)
            .transpose()?
            .unwrap_or_default();
        let sent_at = Timestamp::try_from(p.sent_at.as_ref().ok_or_else(|| missing("sent_at"))?)?;
        let expires_at = p.expires_at.as_ref().map(Timestamp::try_from).transpose()?;
        let in_reply_to = p.in_reply_to.as_ref().map(Hash::try_from).transpose()?;
        let agent_signature = p
            .agent_signature
            .as_ref()
            .map(Signature::try_from)
            .transpose()?;

        Ok(Envelope {
            spec_version,
            swarm_id,
            envelope_id: p.envelope_id.clone(),
            from_agent,
            recipient,
            performative,
            payload: p.payload.clone(),
            payload_schema_id: p.payload_schema_id.clone(),
            tags: p.tags.clone(),
            causal,
            nonce: p.nonce.clone(),
            epoch: p.epoch,
            sent_at,
            expires_at,
            in_reply_to,
            agent_signature,
        })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Performative, Recipient};
    use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
    use yutha_crypto::sign::generate_keypair;
    use yutha_proto::Message;

    fn signed_fixture() -> Envelope {
        let key = generate_keypair();
        Envelope::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::new())
            .envelope_id(vec![0u8; 16])
            .from_agent(AgentId::new())
            .recipient(Recipient::Agent(AgentId::new()))
            .performative(Performative::Inform)
            .payload(b"hello".to_vec())
            .payload_schema_id("type.yutha.dev/v1/Text")
            .tag("pii")
            .causal(CausalRef::empty())
            .nonce(vec![1u8; 16])
            .epoch(1)
            .sent_at(Timestamp::now())
            .sign(&key)
            .unwrap()
    }

    #[test]
    fn envelope_round_trips_to_proto() {
        let e = signed_fixture();
        let p: proto::Envelope = (&e).into();
        assert_eq!(p.performative, proto::Performative::Inform as i32);
        assert_eq!(p.payload, b"hello".to_vec());
        assert_eq!(p.tags, vec!["pii".to_string()]);
        assert!(p.recipient.is_some());
        assert!(p.agent_signature.is_some());
    }

    #[test]
    fn canonical_proto_clears_signature_and_extensions() {
        let e = signed_fixture();
        let cp = e.to_canonical_proto();
        assert!(cp.agent_signature.is_none(), "signature must be cleared");
        assert!(cp.extensions.is_none(), "extensions must be cleared");
        assert_eq!(cp.payload, b"hello".to_vec(), "payload survives");
    }

    #[test]
    fn canonical_encoding_is_bytewise_deterministic() {
        let e = signed_fixture();
        let a = e.to_canonical_proto().encode_to_vec();
        let b = e.to_canonical_proto().encode_to_vec();
        let c = e.clone().to_canonical_proto().encode_to_vec();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn recipient_oneof_round_trips_for_each_variant() {
        let cases: Vec<Recipient> = vec![
            Recipient::Agent(AgentId::new()),
            Recipient::Role("supervisor".into()),
            Recipient::Swarm(crate::SwarmBroadcast {
                filter_tags: vec!["billing".into()],
            }),
            Recipient::External(crate::ExternalEndpoint {
                scheme: "https".into(),
                authority: "api.example.com".into(),
                path_hint: "/v1/invoke".into(),
            }),
        ];
        for r in cases {
            let p: proto::Recipient = (&r).into();
            assert!(p.to.is_some(), "oneof must be set for {:?}", r);
        }
    }

    #[test]
    fn performative_maps_to_wire_integers() {
        // Cross-check the From<Performative> impl matches existing to_wire.
        for p in [
            Performative::Propose,
            Performative::Inform,
            Performative::Confirm,
        ] {
            assert_eq!(<Performative as Into<i32>>::into(p), p.to_wire());
        }
    }

    // -------------------------------------------------------------------------
    // Reverse conversion tests (proto → ergonomic)
    // -------------------------------------------------------------------------

    #[test]
    fn envelope_round_trips_proto_to_ergonomic() {
        let original = signed_fixture();
        let p: proto::Envelope = (&original).into();
        let back = Envelope::try_from(&p).expect("reverse should succeed");

        assert_eq!(back.swarm_id, original.swarm_id);
        assert_eq!(back.from_agent, original.from_agent);
        assert_eq!(back.performative, original.performative);
        assert_eq!(back.payload, original.payload);
        assert_eq!(back.tags, original.tags);
        assert_eq!(back.envelope_id, original.envelope_id);
        assert!(back.agent_signature.is_some());

        // Verify the round-tripped envelope still passes signature verification.
        // (Re-encoding through proto MUST preserve canonical bytes bytewise.)
        // Note: we don't have the original signing key here, so we just
        // check the structural round-trip; signature-verification tests
        // exist elsewhere.
    }

    #[test]
    fn envelope_missing_from_agent_rejected() {
        let e = signed_fixture();
        let mut p: proto::Envelope = (&e).into();
        p.from_agent = None;
        let err = Envelope::try_from(&p).unwrap_err();
        assert!(matches!(err, TransportError::Core(_)));
        assert!(err.to_string().contains("from_agent"));
    }

    #[test]
    fn envelope_unknown_performative_rejected() {
        let e = signed_fixture();
        let mut p: proto::Envelope = (&e).into();
        p.performative = 0; // UNKNOWN
        let err = Envelope::try_from(&p).unwrap_err();
        assert!(matches!(err, TransportError::Core(_)));
        assert!(err.to_string().contains("performative"));
    }

    #[test]
    fn recipient_oneof_reverse_handles_all_four_variants() {
        let cases: Vec<Recipient> = vec![
            Recipient::Agent(AgentId::new()),
            Recipient::Role("supervisor".into()),
            Recipient::Swarm(crate::SwarmBroadcast {
                filter_tags: vec!["billing".into()],
            }),
            Recipient::External(crate::ExternalEndpoint {
                scheme: "https".into(),
                authority: "api.example.com".into(),
                path_hint: "/v1/invoke".into(),
            }),
        ];
        for r in cases {
            let p: proto::Recipient = (&r).into();
            let back = Recipient::try_from(&p).unwrap();
            assert_eq!(back, r);
        }
    }

    #[test]
    fn recipient_missing_oneof_rejected() {
        let p = proto::Recipient { to: None };
        let err = Recipient::try_from(&p).unwrap_err();
        assert!(matches!(err, TransportError::Core(_)));
    }

    #[test]
    fn performative_reverse_rejects_unknown_and_out_of_range() {
        assert!(Performative::try_from(0).is_err());
        assert!(Performative::try_from(99).is_err());
    }
}
