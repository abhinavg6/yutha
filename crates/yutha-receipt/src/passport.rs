//! [`PassportResolver`] — async lookup from agent/role to public key.
//!
//! The receipt store calls a resolver during [`crate::ReceiptStore::append`]
//! to find the public keys needed to verify the receipt's signatures. The
//! actual passport store (a full Workstream B crate) implements this trait;
//! tests use [`StaticPassportResolver`] as a stand-in.
//!
//! This trait deliberately lives here, not in a separate `yutha-passport`
//! crate, because:
//! - It's the smallest possible surface the receipt store needs.
//! - Keeping it here lets `yutha-receipt` be self-contained and testable
//!   without depending on the full passport crate.
//! - The full passport crate (when it lands) will provide its own
//!   `impl PassportResolver` adapter on top of its store.

use crate::error::Result;
use crate::signing::SignatureRole;
use async_trait::async_trait;
use std::collections::HashMap;
use yutha_core::{AgentId, PublicKey};

/// Looks up the public key for an actor or a signature role.
///
/// Implementations are typically backed by a passport store. For non-actor
/// signature roles (control plane, supervisor, attestation), the resolver
/// keys on `(role, key_fingerprint)` so that callers can identify which of
/// (potentially several) keys with that role produced the signature.
///
/// Returning `Ok(None)` means "no such key registered" — the receipt store
/// treats this as a verification failure ([`crate::ReceiptError::ActorNotResolvable`]
/// for the actor; non-actor roles where the key is unknown are silently
/// skipped during verification, per the optional-role policy in
/// [`crate::verify::verify_receipt_signatures`]).
#[async_trait]
pub trait PassportResolver: Send + Sync {
    /// Resolve an agent's public key.
    async fn resolve_actor(&self, agent_id: &AgentId) -> Result<Option<PublicKey>>;

    /// Resolve a non-actor signature role's public key by (role, key fingerprint).
    /// Default implementation returns `Ok(None)` (i.e. don't verify optional
    /// roles unless the resolver knows them) — backends that track
    /// control-plane / supervisor / attestation keys override.
    async fn resolve_role(
        &self,
        _role: SignatureRole,
        _key_fingerprint: &[u8],
    ) -> Result<Option<PublicKey>> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// StaticPassportResolver — test/dev helper
// ---------------------------------------------------------------------------

/// In-memory passport resolver useful for tests and the embedded quickstart.
///
/// Build with [`StaticPassportResolver::builder`]; add actors and optional
/// roles; build into a usable resolver. Not for production: no persistence,
/// no rotation, no observability.
#[derive(Debug, Clone, Default)]
pub struct StaticPassportResolver {
    actors: HashMap<AgentId, PublicKey>,
    roles: HashMap<(SignatureRole, Vec<u8>), PublicKey>,
}

impl StaticPassportResolver {
    /// Empty resolver. Add entries via [`with_actor`] / [`with_role`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an actor's public key.
    pub fn with_actor(mut self, agent_id: AgentId, key: PublicKey) -> Self {
        self.actors.insert(agent_id, key);
        self
    }

    /// Register a non-actor role's public key.
    pub fn with_role(
        mut self,
        role: SignatureRole,
        key_fingerprint: Vec<u8>,
        key: PublicKey,
    ) -> Self {
        self.roles.insert((role, key_fingerprint), key);
        self
    }

    /// Construct a new builder. Alias for [`new`] for fluent-style readers.
    pub fn builder() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PassportResolver for StaticPassportResolver {
    async fn resolve_actor(&self, agent_id: &AgentId) -> Result<Option<PublicKey>> {
        Ok(self.actors.get(agent_id).cloned())
    }

    async fn resolve_role(
        &self,
        role: SignatureRole,
        key_fingerprint: &[u8],
    ) -> Result<Option<PublicKey>> {
        Ok(self.roles.get(&(role, key_fingerprint.to_vec())).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_core::SignatureAlgorithm;

    fn dummy_key() -> PublicKey {
        PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32]).unwrap()
    }

    #[tokio::test]
    async fn static_resolver_returns_known_actor() {
        let alice = AgentId::new();
        let resolver = StaticPassportResolver::new().with_actor(alice, dummy_key());
        let result = resolver.resolve_actor(&alice).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn static_resolver_returns_none_for_unknown_actor() {
        let resolver = StaticPassportResolver::new();
        let result = resolver.resolve_actor(&AgentId::new()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn static_resolver_returns_none_for_unknown_role() {
        let resolver = StaticPassportResolver::new();
        let result = resolver
            .resolve_role(SignatureRole::Supervisor, &[0u8; 32])
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
