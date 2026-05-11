//! [`Envelope`] — typed wrapper around every agent-to-agent message.

use crate::error::TransportError;
use crate::performative::Performative;
use crate::recipient::Recipient;
use yutha_core::{AgentId, CausalRef, Hash, Signature, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::Result as CryptoResult;
use yutha_proto::Message;

/// A typed, signed message wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Envelope {
    /// Spec version.
    pub spec_version: SpecVersion,
    /// Swarm in which this envelope is valid.
    pub swarm_id: SwarmId,
    /// Envelope identifier (UUID v7, 16 bytes). Distinct from content-address.
    pub envelope_id: Vec<u8>,
    /// Sender.
    pub from_agent: AgentId,
    /// Addressed recipient.
    pub recipient: Recipient,
    /// Speech-act kind.
    pub performative: Performative,
    /// Application payload (opaque to the substrate).
    pub payload: Vec<u8>,
    /// Schema identifier for the payload (e.g. `"yutha.support.v1.TicketUpdate"`).
    pub payload_schema_id: String,
    /// Free-form classification tags applied by the SDK adapter.
    pub tags: Vec<String>,
    /// Causal predecessors. Empty only for genesis.
    pub causal: CausalRef,
    /// Replay-prevention nonce (16 random bytes).
    pub nonce: Vec<u8>,
    /// Replay-prevention epoch (monotonic per-sender).
    pub epoch: u64,
    /// When constructed.
    pub sent_at: Timestamp,
    /// TTL beyond which the envelope MUST NOT be processed.
    pub expires_at: Option<Timestamp>,
    /// Optional reply-to: content-address of the envelope being replied to.
    pub in_reply_to: Option<Hash>,
    /// Sender's signature.
    pub agent_signature: Option<Signature>,
}

impl Envelope {
    /// Builder.
    pub fn builder() -> EnvelopeBuilder {
        EnvelopeBuilder::default()
    }

    /// Whether the envelope has expired relative to `now`.
    pub fn is_expired_at(&self, now: &Timestamp) -> bool {
        self.expires_at
            .as_ref()
            .map(|e| e.monotonic_ns <= now.monotonic_ns)
            .unwrap_or(false)
    }

    /// Verify the sender's signature against the supplied public key.
    pub fn verify_signature(
        &self,
        sender_public_key: &yutha_core::PublicKey,
    ) -> Result<(), TransportError> {
        let sig = self
            .agent_signature
            .as_ref()
            .ok_or(TransportError::EnvelopeRejected(
                crate::error::EnvelopeError::SignatureInvalid,
            ))?;
        let bytes = self.canonical_bytes()?;
        yutha_crypto::sign::verify(sender_public_key, &bytes, sig).map_err(|_| {
            TransportError::EnvelopeRejected(crate::error::EnvelopeError::SignatureInvalid)
        })
    }
}

impl Canonical for Envelope {
    /// Canonical bytes for content-addressing and signature.
    ///
    /// Goes through [`Envelope::to_canonical_proto`] (clears
    /// `agent_signature` and `extensions`) and encodes via
    /// `prost::Message::encode_to_vec()`. With tag-sorted field encoding,
    /// the result is bytewise deterministic across runs and across
    /// spec-conforming implementations.
    fn canonical_bytes(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.to_canonical_proto().encode_to_vec())
    }
}

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

/// Builder for [`Envelope`].
#[derive(Debug, Default)]
pub struct EnvelopeBuilder {
    spec_version: Option<SpecVersion>,
    swarm_id: Option<SwarmId>,
    envelope_id: Option<Vec<u8>>,
    from_agent: Option<AgentId>,
    recipient: Option<Recipient>,
    performative: Option<Performative>,
    payload: Vec<u8>,
    payload_schema_id: String,
    tags: Vec<String>,
    causal: Option<CausalRef>,
    nonce: Option<Vec<u8>>,
    epoch: Option<u64>,
    sent_at: Option<Timestamp>,
    expires_at: Option<Timestamp>,
    in_reply_to: Option<Hash>,
}

impl EnvelopeBuilder {
    /// Required: spec version.
    pub fn spec_version(mut self, v: SpecVersion) -> Self {
        self.spec_version = Some(v);
        self
    }
    /// Required: swarm id.
    pub fn swarm_id(mut self, id: SwarmId) -> Self {
        self.swarm_id = Some(id);
        self
    }
    /// Required: envelope id (UUID v7, 16 bytes).
    pub fn envelope_id(mut self, id: Vec<u8>) -> Self {
        self.envelope_id = Some(id);
        self
    }
    /// Required: sender.
    pub fn from_agent(mut self, id: AgentId) -> Self {
        self.from_agent = Some(id);
        self
    }
    /// Required: recipient.
    pub fn recipient(mut self, r: Recipient) -> Self {
        self.recipient = Some(r);
        self
    }
    /// Required: performative.
    pub fn performative(mut self, p: Performative) -> Self {
        self.performative = Some(p);
        self
    }
    /// Optional: payload (bytes).
    pub fn payload(mut self, bytes: Vec<u8>) -> Self {
        self.payload = bytes;
        self
    }
    /// Optional: payload schema id.
    pub fn payload_schema_id(mut self, id: impl Into<String>) -> Self {
        self.payload_schema_id = id.into();
        self
    }
    /// Optional: add a tag.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }
    /// Required: causal ref (use `CausalRef::empty()` for genesis).
    pub fn causal(mut self, c: CausalRef) -> Self {
        self.causal = Some(c);
        self
    }
    /// Required: nonce (16 random bytes from a CSPRNG).
    pub fn nonce(mut self, n: Vec<u8>) -> Self {
        self.nonce = Some(n);
        self
    }
    /// Required: epoch (monotonic per-sender).
    pub fn epoch(mut self, e: u64) -> Self {
        self.epoch = Some(e);
        self
    }
    /// Required: sent-at timestamp.
    pub fn sent_at(mut self, t: Timestamp) -> Self {
        self.sent_at = Some(t);
        self
    }
    /// Optional: expiration.
    pub fn expires_at(mut self, t: Timestamp) -> Self {
        self.expires_at = Some(t);
        self
    }
    /// Optional: reply-to.
    pub fn in_reply_to(mut self, h: Hash) -> Self {
        self.in_reply_to = Some(h);
        self
    }

    /// Build (unsigned).
    pub fn build(self) -> std::result::Result<Envelope, &'static str> {
        Ok(Envelope {
            spec_version: self.spec_version.ok_or("spec_version required")?,
            swarm_id: self.swarm_id.ok_or("swarm_id required")?,
            envelope_id: self.envelope_id.ok_or("envelope_id required")?,
            from_agent: self.from_agent.ok_or("from_agent required")?,
            recipient: self.recipient.ok_or("recipient required")?,
            performative: self.performative.ok_or("performative required")?,
            payload: self.payload,
            payload_schema_id: self.payload_schema_id,
            tags: self.tags,
            causal: self.causal.unwrap_or_default(),
            nonce: self.nonce.ok_or("nonce required")?,
            epoch: self.epoch.ok_or("epoch required")?,
            sent_at: self.sent_at.ok_or("sent_at required")?,
            expires_at: self.expires_at,
            in_reply_to: self.in_reply_to,
            agent_signature: None,
        })
    }

    /// Build and sign with the sender's signing key.
    pub fn sign(
        self,
        signing_key: &yutha_crypto::SigningKey,
    ) -> std::result::Result<Envelope, &'static str> {
        let mut e = self.build()?;
        let bytes = e.canonical_bytes().map_err(|_| "canonical bytes failed")?;
        let sig = signing_key.sign_message(&bytes);
        e.agent_signature = Some(sig);
        Ok(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipient::Recipient;
    use yutha_crypto::sign::generate_keypair;

    fn sample_envelope(key: &yutha_crypto::SigningKey) -> Envelope {
        Envelope::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::new())
            .envelope_id(vec![0u8; 16])
            .from_agent(AgentId::new())
            .recipient(Recipient::Agent(AgentId::new()))
            .performative(Performative::Inform)
            .payload(b"hello".to_vec())
            .payload_schema_id("type.yutha.dev/v1/Text")
            .causal(CausalRef::empty())
            .nonce(vec![1u8; 16])
            .epoch(1)
            .sent_at(Timestamp::now())
            .sign(key)
            .unwrap()
    }

    #[test]
    fn signed_envelope_verifies() {
        let key = generate_keypair();
        let e = sample_envelope(&key);
        assert!(e.verify_signature(&key.public()).is_ok());
    }

    #[test]
    fn tampered_envelope_fails_verification() {
        let key = generate_keypair();
        let mut e = sample_envelope(&key);
        e.payload = b"tampered".to_vec();
        assert!(e.verify_signature(&key.public()).is_err());
    }

    #[test]
    fn envelope_with_wrong_key_fails() {
        let key1 = generate_keypair();
        let key2 = generate_keypair();
        let e = sample_envelope(&key1);
        assert!(e.verify_signature(&key2.public()).is_err());
    }
}
