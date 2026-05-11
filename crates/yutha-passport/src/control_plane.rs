//! [`ControlPlaneIdentity`] — the control plane's own agent identity.
//!
//! The control plane is itself an agent: it has an AgentId, a signing key,
//! and (typically) a registered passport. When a substrate component
//! (registry, transport, capability store) produces a receipt as a
//! "platform observation" of an agent action, the receipt's `actor` is the
//! control plane and the signature is produced by this identity.
//!
//! This lives in `yutha-passport` so registry, transport, and capability
//! can all share it without dependency cycles.
//!
//! In production, the signing key comes from operator-supplied material
//! (KMS, HSM, sealed file). In tests and the embedded quickstart, it's
//! generated at startup.

use yutha_core::{AgentId, PublicKey, Signature};

/// The control plane's identity. Owns a private signing key; treat as a
/// secret.
pub struct ControlPlaneIdentity {
    /// Stable agent id for the control plane.
    pub agent_id: AgentId,
    signing_key: yutha_crypto::SigningKey,
}

impl ControlPlaneIdentity {
    /// Construct from an existing keypair. Caller is responsible for
    /// ensuring the corresponding passport is registered.
    pub fn new(agent_id: AgentId, signing_key: yutha_crypto::SigningKey) -> Self {
        Self {
            agent_id,
            signing_key,
        }
    }

    /// Generate a fresh identity (fresh AgentId + fresh keypair). Convenient
    /// for tests and the embedded quickstart.
    pub fn generate() -> Self {
        Self::new(AgentId::new(), yutha_crypto::sign::generate_keypair())
    }

    /// Public key of the control-plane's signing key.
    pub fn public_key(&self) -> PublicKey {
        self.signing_key.public()
    }

    /// Sign `message` with the control-plane's key. Used by substrate
    /// components to produce admission / envelope / check receipts.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign_message(message)
    }
}

impl std::fmt::Debug for ControlPlaneIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneIdentity")
            .field("agent_id", &self.agent_id)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}
