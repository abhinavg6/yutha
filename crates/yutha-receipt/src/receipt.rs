//! [`Receipt`] and [`ReceiptBuilder`].
//!
//! Mirrors `Receipt` from
//! [`/spec/receipt/receipt-v1.proto`](../../../spec/receipt/receipt-v1.proto).
//!
//! A `Receipt` is content-addressable: the receipt's identifier is the hash
//! of its canonical serialization with all `signatures` and seal state
//! cleared. As of this revision, canonicalization goes through the prost
//! bindings in [`yutha_proto::receipt::v1`], which gives us deterministic,
//! cross-language wire-equivalent bytes (prost emits tag-sorted fields and
//! `yutha-proto`'s `build.rs` configures map fields as `BTreeMap` for
//! sorted-key encoding).

use crate::evidence::Evidence;
use crate::seal::SealStatus;
use crate::signing::SignedBy;
use yutha_core::{AgentId, CausalRef, CostAnnotation, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::Result as CryptoResult;
use yutha_proto::Message;

/// A signed, content-addressed record of a consequential action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Receipt {
    /// Spec version this receipt was produced under.
    pub spec_version: SpecVersion,

    /// Swarm in which this action occurred.
    pub swarm_id: SwarmId,

    /// The agent that performed the action.
    pub actor: AgentId,

    /// Canonical action-kind string (e.g. `"envelope.send"`,
    /// `"capability.check.deny"`). See spec rationale §3 for the v1.0
    /// taxonomy.
    pub action_kind: String,

    /// Causal predecessors. Empty only for the genesis receipt of a chain.
    pub causal: CausalRef,

    /// Typed inputs/outputs of the action.
    pub evidence: Vec<Evidence>,

    /// Constitution version active at decision time.
    pub constitution_version: String,

    /// Cost annotation. Optional but encouraged.
    pub cost: Option<CostAnnotation>,

    /// When the action occurred.
    pub occurred_at: Timestamp,

    /// Sealing state. Set by the receipt store, not the producer.
    pub seal: SealStatus,

    /// Signatures, in canonical wire order. AT LEAST the actor must sign.
    pub signatures: Vec<SignedBy>,
}

impl Receipt {
    /// Builder for constructing receipts. See [`ReceiptBuilder`].
    pub fn builder() -> ReceiptBuilder {
        ReceiptBuilder::new()
    }

    /// Whether this receipt has been sealed into a Merkle batch.
    pub fn is_sealed(&self) -> bool {
        matches!(self.seal.state, crate::seal::SealState::Sealed)
    }
}

impl Canonical for Receipt {
    /// Produce the canonical byte sequence for content-addressing.
    ///
    /// Encoding path:
    ///
    /// 1. Convert to the prost-generated [`yutha_proto::receipt::v1::Receipt`]
    ///    via [`Receipt::to_canonical_proto`]. That step clears `signatures`,
    ///    normalizes `seal` to `None`, and drops `extensions` (receipts are
    ///    content-addressed *before* they are signed or sealed).
    /// 2. Encode the proto message with `prost::Message::encode_to_vec()`.
    ///    prost emits fields in tag-sorted order; combined with `btree_map`
    ///    configuration in `yutha-proto`'s build, the result is bytewise
    ///    deterministic both within a single Rust process and across
    ///    spec-conforming implementations in other languages.
    ///
    /// Signatures and seal state are deliberately excluded — see receipt
    /// rationale §1 ("the receipt's identifier is stable regardless of who
    /// eventually signs").
    fn canonical_bytes(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.to_canonical_proto().encode_to_vec())
    }
}

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

/// Builder for [`Receipt`].
#[derive(Debug, Default)]
pub struct ReceiptBuilder {
    spec_version: Option<SpecVersion>,
    swarm_id: Option<SwarmId>,
    actor: Option<AgentId>,
    action_kind: Option<String>,
    causal: Option<CausalRef>,
    evidence: Vec<Evidence>,
    constitution_version: Option<String>,
    cost: Option<CostAnnotation>,
    occurred_at: Option<Timestamp>,
    seal: Option<SealStatus>,
    signatures: Vec<SignedBy>,
}

impl ReceiptBuilder {
    /// New empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set spec version.
    pub fn spec_version(mut self, v: SpecVersion) -> Self {
        self.spec_version = Some(v);
        self
    }

    /// Set swarm id.
    pub fn swarm_id(mut self, id: SwarmId) -> Self {
        self.swarm_id = Some(id);
        self
    }

    /// Set actor.
    pub fn actor(mut self, id: AgentId) -> Self {
        self.actor = Some(id);
        self
    }

    /// Set action kind.
    pub fn action_kind(mut self, kind: impl Into<String>) -> Self {
        self.action_kind = Some(kind.into());
        self
    }

    /// Set causal ref.
    pub fn causal(mut self, c: CausalRef) -> Self {
        self.causal = Some(c);
        self
    }

    /// Add a piece of evidence.
    pub fn evidence(mut self, e: Evidence) -> Self {
        self.evidence.push(e);
        self
    }

    /// Set constitution version.
    pub fn constitution_version(mut self, v: impl Into<String>) -> Self {
        self.constitution_version = Some(v.into());
        self
    }

    /// Set cost annotation.
    pub fn cost(mut self, c: CostAnnotation) -> Self {
        self.cost = Some(c);
        self
    }

    /// Set occurred-at timestamp.
    pub fn occurred_at(mut self, t: Timestamp) -> Self {
        self.occurred_at = Some(t);
        self
    }

    /// Add a signature. Order matters; callers should add in canonical wire
    /// order (Actor → ControlPlane → Supervisor → Attestation → BatchRoot).
    pub fn signed_by(mut self, sig: SignedBy) -> Self {
        self.signatures.push(sig);
        self
    }

    /// Finalize. Returns an error if required fields are unset.
    pub fn build(self) -> Result<Receipt, &'static str> {
        Ok(Receipt {
            spec_version: self.spec_version.ok_or("spec_version required")?,
            swarm_id: self.swarm_id.ok_or("swarm_id required")?,
            actor: self.actor.ok_or("actor required")?,
            action_kind: self.action_kind.ok_or("action_kind required")?,
            causal: self.causal.unwrap_or_default(),
            evidence: self.evidence,
            constitution_version: self
                .constitution_version
                .ok_or("constitution_version required")?,
            cost: self.cost,
            occurred_at: self.occurred_at.ok_or("occurred_at required")?,
            seal: self.seal.unwrap_or_default(),
            signatures: self.signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_crypto::canonical::content_address;

    fn fixture() -> Receipt {
        Receipt::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::new())
            .actor(AgentId::new())
            .action_kind("envelope.send")
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::now())
            .build()
            .unwrap()
    }

    #[test]
    fn builder_requires_required_fields() {
        let result = Receipt::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let r = fixture();
        let a = r.canonical_bytes().unwrap();
        let b = r.canonical_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_bytes_exclude_signatures_and_seal() {
        let r1 = fixture();

        let mut r2 = r1.clone();
        r2.signatures.push(SignedBy::new(
            crate::signing::SignatureRole::Actor,
            yutha_core::Signature::new(
                yutha_core::SignatureAlgorithm::Ed25519,
                vec![0u8; 64],
                vec![0u8; 32],
            )
            .unwrap(),
            Timestamp::now(),
        ));

        // Adding a signature MUST NOT change the canonical bytes.
        let bytes_a = r1.canonical_bytes().unwrap();
        let bytes_b = r2.canonical_bytes().unwrap();
        assert_eq!(bytes_a, bytes_b);

        // ...nor change the content-address.
        let addr_a = content_address(&r1).unwrap();
        let addr_b = content_address(&r2).unwrap();
        assert_eq!(addr_a, addr_b);
    }

    #[test]
    fn distinct_receipts_have_distinct_addresses() {
        let r1 = fixture();
        let r2 = fixture(); // different ids/timestamps
        let a1 = content_address(&r1).unwrap();
        let a2 = content_address(&r2).unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn canonical_bytes_are_bytewise_deterministic_for_clones() {
        // Two structurally-identical receipts (same logical content, distinct
        // allocations) must encode to identical bytes. This is the strongest
        // local check we can do without a second-language implementation; the
        // conformance suite tightens this to cross-language equivalence.
        let r1 = fixture();
        let r2 = r1.clone();
        assert_eq!(
            r1.canonical_bytes().unwrap(),
            r2.canonical_bytes().unwrap(),
            "clones must canonicalize to identical bytes"
        );
    }
}
