//! Conversions between ergonomic [`yutha-core`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! The conversions go one way: ergonomic → proto. Reverse conversions can
//! be added if a use case emerges (currently the substrate doesn't decode
//! proto into ergonomic types in any hot path).

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
}
