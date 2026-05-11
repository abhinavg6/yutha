//! Conversions between ergonomic [`yutha-transport`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! Same pattern as `yutha-receipt::proto_conv` and `yutha-passport::proto_conv`:
//! ergonomic → proto, one way. Used for content-addressing and signature
//! verification through [`Envelope::to_canonical_proto`].

use crate::{Envelope, ExternalEndpoint, Performative, Recipient, SwarmBroadcast};
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
}
