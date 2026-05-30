//! [`ControlPlaneIdentity`] — the control plane's own agent identity.
//!
//! The control plane is itself an agent: it has an AgentId, a signing
//! capability, and (typically) a registered passport. When a substrate
//! component (registry, transport, capability store) produces a receipt as a
//! "platform observation" of an agent action, the receipt's `actor` is the
//! control plane and the signature is produced by this identity.
//!
//! This lives in `yutha-passport` so registry, transport, and capability
//! can all share it without dependency cycles.
//!
//! In production the signing capability is a cloud-KMS-backed
//! [`yutha_signer::Signer`]; in tests and the embedded quickstart it's an
//! [`InProcessSigner`](yutha_signer::InProcessSigner) wrapping a fresh
//! keypair. Either way, this struct holds only a `Signer` handle — it does
//! NOT hold raw key bytes. The control plane's key material lives wherever
//! the operator put it (process memory for InProcess, cloud KMS for
//! managed). See [RFC 0015](../../../spec/rfcs/0015-signer-interface.md).

use std::sync::Arc;
use yutha_core::{AgentId, PublicKey, Signature};
use yutha_signer::{Signer, SignerError};

/// The control plane's identity.
///
/// Holds an `Arc<dyn Signer>` rather than raw key bytes — this is the load-
/// bearing piece of the RFC 0015 refactor for the control plane's own
/// signing path. Every internal call site that previously called
/// `state.control_plane_identity.sign(&bytes)` now awaits an async
/// signing operation; for `InProcessSigner` that's effectively zero-cost,
/// for cloud-KMS-backed signers it's one network round-trip per receipt.
#[derive(Clone)]
pub struct ControlPlaneIdentity {
    /// Stable agent id for the control plane.
    pub agent_id: AgentId,
    /// The signer that produces this identity's signatures.
    signer: Arc<dyn Signer>,
    /// Cached public key, fetched from `signer.public_key()` at
    /// construction. Avoids re-traversing the trait object on every
    /// access (the trait contract makes `public_key()` cheap, but for hot
    /// paths the local cache is still a touch faster).
    public_key: PublicKey,
}

impl ControlPlaneIdentity {
    /// Construct from an explicit AgentId + a signer handle.
    ///
    /// Caller is responsible for ensuring the corresponding passport is
    /// registered (typically: at control-plane startup, mint a passport
    /// for this AgentId using `signer` as the signing capability, register
    /// it through the same flow agents use).
    pub fn new(agent_id: AgentId, signer: Arc<dyn Signer>) -> Self {
        let public_key = signer.public_key();
        Self {
            agent_id,
            signer,
            public_key,
        }
    }

    /// Generate a fresh identity (fresh AgentId + fresh
    /// [`InProcessSigner`](yutha_signer::InProcessSigner)). Test / embedded-
    /// quickstart convenience.
    pub fn generate() -> Self {
        let signer: Arc<dyn Signer> = Arc::new(yutha_signer::InProcessSigner::generate());
        Self::new(AgentId::new(), signer)
    }

    /// Public key of the control-plane's signing capability.
    ///
    /// Sync and infallible by trait contract (RFC 0015 §3.1 invariant 3).
    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    /// Borrow the underlying signer handle.
    ///
    /// Useful when a substrate call wants to thread the same signer
    /// through to a helper that takes `&dyn Signer` directly (e.g.,
    /// signing a `Passport` for the control plane's own self-registration).
    pub fn signer(&self) -> &Arc<dyn Signer> {
        &self.signer
    }

    /// Sign `message` with the control-plane's key. Used by substrate
    /// components to produce admission / envelope / check / constitution /
    /// enforcement receipts.
    ///
    /// Async: for `InProcessSigner` this completes immediately; for cloud-
    /// KMS-backed signers it's one network round-trip.
    pub async fn sign(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.signer.sign_message(message).await
    }
}

impl std::fmt::Debug for ControlPlaneIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneIdentity")
            .field("agent_id", &self.agent_id)
            .field("signer", &"<redacted>")
            .finish()
    }
}
