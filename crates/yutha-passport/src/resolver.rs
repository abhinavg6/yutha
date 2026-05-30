//! [`PassportResolverAdapter`] — bridges a [`PassportStore`] into the
//! [`yutha_receipt::PassportResolver`] trait so the receipt store can verify
//! signatures against registered passports.
//!
//! This is the integration point between yutha-passport (Workstream B) and
//! yutha-receipt (Workstream C). Without it, the receipt store has no way
//! to look up an agent's public key.

use crate::error::PassportError;
use crate::store::PassportStore;
use async_trait::async_trait;
use std::sync::Arc;
use yutha_core::{AgentId, PublicKey};
use yutha_receipt::{PassportResolver, ReceiptError};

/// Adapter wrapping a [`PassportStore`] to satisfy [`PassportResolver`].
///
/// Construct with [`PassportResolverAdapter::new`] passing in any
/// `Arc<dyn PassportStore>` — typically the in-memory store in tests and a
/// persistent backend in production.
pub struct PassportResolverAdapter {
    store: Arc<dyn PassportStore>,
}

impl PassportResolverAdapter {
    /// Construct an adapter around any passport-store implementation.
    pub fn new(store: Arc<dyn PassportStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl PassportResolver for PassportResolverAdapter {
    async fn resolve_actor(
        &self,
        agent_id: &AgentId,
    ) -> std::result::Result<Option<PublicKey>, ReceiptError> {
        self.store
            .lookup(agent_id)
            .await
            .map(|opt| opt.map(|p| p.agent_public_key))
            .map_err(passport_err_to_receipt_err)
    }

    // resolve_role uses the default impl (returns None) — non-actor role
    // resolution is the registry/capability layer's job, not the passport
    // store's. A future enrichment could route control-plane and supervisor
    // role keys through here, but at scaffolding level we leave them to be
    // resolved by callers that hold the right registries.
}

/// Map passport-layer errors to receipt-layer errors. Most map to
/// `ReceiptError::PassportResolver(...)` since they're transient/backend
/// failures from the receipt store's perspective.
fn passport_err_to_receipt_err(e: PassportError) -> ReceiptError {
    match e {
        PassportError::NotFound(_) => {
            // Not really an error at the resolver layer — return Ok(None)
            // via a different path. But the lookup returned an error here,
            // so surface it as backend.
            ReceiptError::PassportResolver(format!("{e}"))
        }
        other => ReceiptError::PassportResolver(format!("{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryPassportStore;
    use crate::passport::Passport;
    use crate::tier::PassportTier;
    use yutha_core::{SpecVersion, SwarmId, Timestamp};
    use yutha_signer::InProcessSigner;

    async fn signed_passport(agent_id: AgentId) -> (Passport, PublicKey) {
        let signer = InProcessSigner::generate();
        let pk = signer.public_key();
        let p = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(SwarmId::new())
            .agent_public_key(pk.clone())
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&signer)
            .await
            .unwrap();
        (p, pk)
    }

    #[tokio::test]
    async fn adapter_resolves_registered_agent() {
        let store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let agent_id = AgentId::new();
        let (p, pk) = signed_passport(agent_id).await;
        store.register(p).await.unwrap();

        let adapter = PassportResolverAdapter::new(store);
        let resolved = adapter.resolve_actor(&agent_id).await.unwrap();
        assert_eq!(resolved, Some(pk));
    }

    #[tokio::test]
    async fn adapter_returns_none_for_unknown_agent() {
        let store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let adapter = PassportResolverAdapter::new(store);
        let resolved = adapter.resolve_actor(&AgentId::new()).await.unwrap();
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn adapter_returns_none_for_revoked_agent() {
        let store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let agent_id = AgentId::new();
        let (p, _pk) = signed_passport(agent_id).await;
        store.register(p).await.unwrap();
        store.revoke(&agent_id, "test").await.unwrap();

        let adapter = PassportResolverAdapter::new(store);
        let resolved = adapter.resolve_actor(&agent_id).await.unwrap();
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn adapter_picks_up_key_rotation() {
        let store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let agent_id = AgentId::new();
        let (p1, _pk1) = signed_passport(agent_id).await;
        store.register(p1).await.unwrap();

        let (p2, pk2) = signed_passport(agent_id).await;
        store.rotate_key(p2).await.unwrap();

        let adapter = PassportResolverAdapter::new(store);
        let resolved = adapter.resolve_actor(&agent_id).await.unwrap();
        assert_eq!(resolved, Some(pk2));
    }
}
