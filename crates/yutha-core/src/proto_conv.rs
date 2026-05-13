//! Conversions between ergonomic [`yutha-core`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! Conversions go both directions:
//!
//! - **`From<&Ergonomic> for Proto`** — infallible. Used for
//!   content-addressing, signing, and constructing wire responses.
//! - **`TryFrom<&Proto> for Ergonomic`** — fallible. Used by the
//!   control-plane gRPC server (and other code paths consuming wire
//!   input) to decode bytes-from-untrusted-source into ergonomic
//!   types that enforce invariants (correct length, valid enum value,
//!   parseable timestamp, etc.). Errors surface as [`CoreError`].
//!
//! Reverse impls take `&Proto` rather than `Proto` so the caller keeps
//! ownership of the wire message — useful when the same proto value
//! needs to be inspected for multiple ergonomic conversions.

use crate::{
    AgentId, CausalRef, CostAnnotation, Hash, HashAlgorithm, PublicKey, Signature,
    SignatureAlgorithm, SpecVersion, SwarmId, Timestamp,
};
use yutha_proto::common::v1 as proto;

impl From<&AgentId> for proto::AgentId {
    fn from(id: &AgentId) -> Self {
        proto::AgentId {
            value: id.as_bytes().to_vec(),
        }
    }
}

impl From<&SwarmId> for proto::SwarmId {
    fn from(id: &SwarmId) -> Self {
        proto::SwarmId {
            value: id.as_bytes().to_vec(),
        }
    }
}

impl From<HashAlgorithm> for i32 {
    fn from(alg: HashAlgorithm) -> Self {
        match alg {
            HashAlgorithm::Sha256 => proto::HashAlgorithm::Sha256 as i32,
            HashAlgorithm::Blake3 => proto::HashAlgorithm::Blake3 as i32,
        }
    }
}

impl From<&Hash> for proto::Hash {
    fn from(h: &Hash) -> Self {
        proto::Hash {
            algorithm: h.algorithm.into(),
            digest: h.digest.clone(),
        }
    }
}

impl From<SignatureAlgorithm> for i32 {
    fn from(alg: SignatureAlgorithm) -> Self {
        match alg {
            SignatureAlgorithm::Ed25519 => proto::SignatureAlgorithm::Ed25519 as i32,
            SignatureAlgorithm::ReservedPq => proto::SignatureAlgorithm::ReservedPq as i32,
        }
    }
}

impl From<&Signature> for proto::Signature {
    fn from(s: &Signature) -> Self {
        proto::Signature {
            algorithm: s.algorithm.into(),
            value: s.value.clone(),
            key_fingerprint: s.key_fingerprint.clone(),
        }
    }
}

impl From<&PublicKey> for proto::PublicKey {
    fn from(pk: &PublicKey) -> Self {
        proto::PublicKey {
            algorithm: pk.algorithm.into(),
            value: pk.value.clone(),
        }
    }
}

impl From<&Timestamp> for proto::Timestamp {
    fn from(t: &Timestamp) -> Self {
        proto::Timestamp {
            wall_clock: t.wall_clock.clone(),
            monotonic_ns: t.monotonic_ns,
        }
    }
}

impl From<&CausalRef> for proto::CausalRef {
    fn from(c: &CausalRef) -> Self {
        proto::CausalRef {
            predecessors: c.predecessors.iter().map(Into::into).collect(),
        }
    }
}

impl From<&SpecVersion> for proto::Version {
    fn from(v: &SpecVersion) -> Self {
        proto::Version { value: v.0.clone() }
    }
}

impl From<&CostAnnotation> for proto::CostAnnotation {
    fn from(c: &CostAnnotation) -> Self {
        proto::CostAnnotation {
            input_tokens: c.input_tokens,
            output_tokens: c.output_tokens,
            tool_call_count: c.tool_call_count,
            wall_time_ms: c.wall_time_ms,
            usd_cents_estimate: c.usd_cents_estimate.clone(),
            model_provider: c.model_provider.clone(),
            model_name: c.model_name.clone(),
            model_version: c.model_version.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Reverse conversions: proto → ergonomic.
//
// All fallible (`TryFrom`) because proto3 messages can carry invalid data:
// wrong-length byte fields, unknown enum values, unparseable timestamps,
// missing nested-message fields that proto3 models as `Option<T>` but the
// ergonomic types treat as required.
//
// Returning `CoreError` keeps the error surface uniform; callers in the
// gRPC layer map this to `tonic::Status::invalid_argument(...)`.
// -----------------------------------------------------------------------------

impl TryFrom<&proto::AgentId> for AgentId {
    type Error = crate::CoreError;
    fn try_from(p: &proto::AgentId) -> Result<Self, Self::Error> {
        AgentId::from_bytes(&p.value)
    }
}

impl TryFrom<&proto::SwarmId> for SwarmId {
    type Error = crate::CoreError;
    fn try_from(p: &proto::SwarmId) -> Result<Self, Self::Error> {
        SwarmId::from_bytes(&p.value)
    }
}

impl TryFrom<&proto::Hash> for Hash {
    type Error = crate::CoreError;
    fn try_from(p: &proto::Hash) -> Result<Self, Self::Error> {
        let algorithm = HashAlgorithm::from_wire(p.algorithm)?;
        Hash::new(algorithm, p.digest.clone())
    }
}

impl TryFrom<&proto::Signature> for Signature {
    type Error = crate::CoreError;
    fn try_from(p: &proto::Signature) -> Result<Self, Self::Error> {
        let algorithm = SignatureAlgorithm::from_wire(p.algorithm)?;
        Signature::new(algorithm, p.value.clone(), p.key_fingerprint.clone())
    }
}

impl TryFrom<&proto::PublicKey> for PublicKey {
    type Error = crate::CoreError;
    fn try_from(p: &proto::PublicKey) -> Result<Self, Self::Error> {
        let algorithm = SignatureAlgorithm::from_wire(p.algorithm)?;
        PublicKey::new(algorithm, p.value.clone())
    }
}

impl TryFrom<&proto::Timestamp> for Timestamp {
    type Error = crate::CoreError;
    fn try_from(p: &proto::Timestamp) -> Result<Self, Self::Error> {
        Timestamp::new(p.wall_clock.clone(), p.monotonic_ns)
    }
}

impl TryFrom<&proto::CausalRef> for CausalRef {
    type Error = crate::CoreError;
    fn try_from(p: &proto::CausalRef) -> Result<Self, Self::Error> {
        let mut predecessors = Vec::with_capacity(p.predecessors.len());
        for h in &p.predecessors {
            predecessors.push(Hash::try_from(h)?);
        }
        Ok(CausalRef::from_iter(predecessors))
    }
}

impl TryFrom<&proto::Version> for SpecVersion {
    type Error = crate::CoreError;
    fn try_from(p: &proto::Version) -> Result<Self, Self::Error> {
        SpecVersion::parse(&p.value)
    }
}

impl TryFrom<&proto::CostAnnotation> for CostAnnotation {
    type Error = crate::CoreError;
    fn try_from(p: &proto::CostAnnotation) -> Result<Self, Self::Error> {
        Ok(CostAnnotation {
            input_tokens: p.input_tokens,
            output_tokens: p.output_tokens,
            tool_call_count: p.tool_call_count,
            wall_time_ms: p.wall_time_ms,
            usd_cents_estimate: p.usd_cents_estimate.clone(),
            model_provider: p.model_provider.clone(),
            model_name: p.model_name.clone(),
            model_version: p.model_version.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_proto::Message;

    #[test]
    fn agent_id_round_trips_bytes() {
        let id = AgentId::new();
        let proto_id: proto::AgentId = (&id).into();
        assert_eq!(proto_id.value, id.as_bytes().to_vec());
    }

    #[test]
    fn hash_encodes_deterministically() {
        let h = Hash::new(HashAlgorithm::Sha256, vec![0xab; 32]).unwrap();
        let p1: proto::Hash = (&h).into();
        let p2: proto::Hash = (&h).into();
        assert_eq!(p1.encode_to_vec(), p2.encode_to_vec());
    }

    #[test]
    fn timestamp_preserves_both_clocks() {
        let t = Timestamp::new("2026-05-10T19:50:00Z".into(), 12345).unwrap();
        let p: proto::Timestamp = (&t).into();
        assert_eq!(p.wall_clock, "2026-05-10T19:50:00Z");
        assert_eq!(p.monotonic_ns, 12345);
    }

    // ---------------------------------------------------------------
    // Reverse-conversion round-trip tests. Each ergonomic value goes
    // ergonomic → proto → ergonomic and must equal the original.
    // ---------------------------------------------------------------

    #[test]
    fn agent_id_round_trip() {
        let id = AgentId::new();
        let p: proto::AgentId = (&id).into();
        let back = AgentId::try_from(&p).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn swarm_id_round_trip() {
        let id = SwarmId::new();
        let p: proto::SwarmId = (&id).into();
        let back = SwarmId::try_from(&p).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn hash_round_trip() {
        let h = Hash::new(HashAlgorithm::Sha256, vec![0xab; 32]).unwrap();
        let p: proto::Hash = (&h).into();
        let back = Hash::try_from(&p).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn signature_round_trip() {
        let s = Signature::new(SignatureAlgorithm::Ed25519, vec![0u8; 64], vec![0u8; 32]).unwrap();
        let p: proto::Signature = (&s).into();
        let back = Signature::try_from(&p).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn public_key_round_trip() {
        let k = PublicKey::new(SignatureAlgorithm::Ed25519, vec![0xcd; 32]).unwrap();
        let p: proto::PublicKey = (&k).into();
        let back = PublicKey::try_from(&p).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn timestamp_round_trip() {
        let t = Timestamp::new("2026-05-10T19:50:00Z".into(), 12345).unwrap();
        let p: proto::Timestamp = (&t).into();
        let back = Timestamp::try_from(&p).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn causal_ref_round_trip_preserves_order() {
        let h1 = Hash::new(HashAlgorithm::Sha256, vec![1u8; 32]).unwrap();
        let h2 = Hash::new(HashAlgorithm::Sha256, vec![2u8; 32]).unwrap();
        let c = CausalRef::from_iter([h1.clone(), h2.clone()]);
        let p: proto::CausalRef = (&c).into();
        let back = CausalRef::try_from(&p).unwrap();
        assert_eq!(back.predecessors, vec![h1, h2]);
    }

    #[test]
    fn cost_annotation_round_trip() {
        let c = CostAnnotation {
            input_tokens: 100,
            output_tokens: 50,
            tool_call_count: 3,
            wall_time_ms: 1500,
            usd_cents_estimate: "12.34".into(),
            model_provider: "anthropic".into(),
            model_name: "claude-opus-4-7".into(),
            model_version: "20260501".into(),
        };
        let p: proto::CostAnnotation = (&c).into();
        let back = CostAnnotation::try_from(&p).unwrap();
        assert_eq!(back, c);
    }

    // ---------------------------------------------------------------
    // Error cases — make sure invalid wire bytes surface as CoreError,
    // not panics. These are the cases the gRPC layer maps to
    // `Status::invalid_argument`.
    // ---------------------------------------------------------------

    #[test]
    fn agent_id_wrong_length_errors() {
        let p = proto::AgentId {
            value: vec![0u8; 15],
        };
        assert!(AgentId::try_from(&p).is_err());
    }

    #[test]
    fn hash_unknown_algorithm_errors() {
        let p = proto::Hash {
            algorithm: 99,
            digest: vec![0u8; 32],
        };
        assert!(Hash::try_from(&p).is_err());
    }

    #[test]
    fn timestamp_unparseable_wall_clock_errors() {
        let p = proto::Timestamp {
            wall_clock: "not a timestamp".into(),
            monotonic_ns: 0,
        };
        assert!(Timestamp::try_from(&p).is_err());
    }
}
