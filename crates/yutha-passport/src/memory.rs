//! [`MemoryPassportStore`] — in-memory reference [`PassportStore`].
//!
//! Tests, conformance fixtures, embedded quickstart. Not for production.

use crate::error::{PassportError, Result};
use crate::passport::Passport;
use crate::registration::{RegistrationOutcome, RegistrationStatus};
use crate::store::PassportStore;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use yutha_core::AgentId;

/// In-memory passport store. Thread-safe via tokio RwLock; cloneable handles
/// share state (`Arc` inside).
#[derive(Debug, Clone, Default)]
pub struct MemoryPassportStore {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    /// agent_id → live passport
    live: HashMap<AgentId, Passport>,
    /// agent_id → revocation reason (presence implies revoked)
    revoked: HashMap<AgentId, String>,
}

impl MemoryPassportStore {
    /// New empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PassportStore for MemoryPassportStore {
    async fn register(&self, passport: Passport) -> Result<RegistrationOutcome> {
        passport.verify_self_signature()?;

        let agent_id = passport.agent_id;
        let mut guard = self.inner.write().await;

        if guard.live.contains_key(&agent_id) {
            return Err(PassportError::AlreadyRegistered(agent_id));
        }
        // If the agent was previously revoked, registration of a fresh
        // passport (new key) is allowed — this is the "reissue" path. The
        // revocation record stays for audit but is shadowed by the live
        // entry. (Real implementations may want to enforce a cooldown.)

        guard.live.insert(agent_id, passport);

        Ok(RegistrationOutcome {
            status: RegistrationStatus::Accepted,
            agent_id,
            registration_receipt: None, // caller wires the receipt-store side.
            rejection_reason: String::new(),
        })
    }

    async fn lookup(&self, agent_id: &AgentId) -> Result<Option<Passport>> {
        let guard = self.inner.read().await;
        if guard.revoked.contains_key(agent_id) && !guard.live.contains_key(agent_id) {
            return Ok(None);
        }
        Ok(guard.live.get(agent_id).cloned())
    }

    async fn revoke(&self, agent_id: &AgentId, reason: &str) -> Result<()> {
        let mut guard = self.inner.write().await;
        if guard.live.remove(agent_id).is_none() {
            return Err(PassportError::NotFound(*agent_id));
        }
        guard.revoked.insert(*agent_id, reason.to_string());
        Ok(())
    }

    async fn rotate_key(&self, new_passport: Passport) -> Result<RegistrationOutcome> {
        new_passport.verify_self_signature()?;

        let agent_id = new_passport.agent_id;
        let mut guard = self.inner.write().await;
        if !guard.live.contains_key(&agent_id) {
            return Err(PassportError::NotFound(agent_id));
        }
        // Continuity check: a real registry would require the old key to
        // counter-sign the new passport's content-address. At this
        // scaffolding level, the registry layer handles that — the store
        // accepts the new passport as a key rotation if the agent is live.
        guard.live.insert(agent_id, new_passport);

        Ok(RegistrationOutcome {
            status: RegistrationStatus::Accepted,
            agent_id,
            registration_receipt: None,
            rejection_reason: String::new(),
        })
    }

    async fn count(&self) -> Result<u64> {
        let guard = self.inner.read().await;
        Ok(guard.live.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passport::Passport;
    use crate::tier::PassportTier;
    use yutha_core::{SpecVersion, SwarmId, Timestamp};
    use yutha_signer::InProcessSigner;

    async fn signed_passport(agent_id: AgentId) -> Passport {
        let signer = InProcessSigner::generate();
        Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(SwarmId::new())
            .agent_public_key(signer.public_key())
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&signer)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn register_then_lookup() {
        let store = MemoryPassportStore::new();
        let agent_id = AgentId::new();
        let p = signed_passport(agent_id).await;
        let outcome = store.register(p.clone()).await.unwrap();
        assert!(outcome.is_accepted());

        let fetched = store.lookup(&agent_id).await.unwrap();
        assert_eq!(fetched, Some(p));
    }

    #[tokio::test]
    async fn duplicate_register_fails() {
        let store = MemoryPassportStore::new();
        let agent_id = AgentId::new();
        let p = signed_passport(agent_id).await;
        store.register(p.clone()).await.unwrap();
        let result = store.register(p).await;
        assert!(matches!(result, Err(PassportError::AlreadyRegistered(_))));
    }

    #[tokio::test]
    async fn revoke_makes_lookup_return_none() {
        let store = MemoryPassportStore::new();
        let agent_id = AgentId::new();
        let p = signed_passport(agent_id).await;
        store.register(p).await.unwrap();

        store.revoke(&agent_id, "test").await.unwrap();
        let fetched = store.lookup(&agent_id).await.unwrap();
        assert_eq!(fetched, None);
    }

    #[tokio::test]
    async fn revoke_unknown_fails() {
        let store = MemoryPassportStore::new();
        let result = store.revoke(&AgentId::new(), "test").await;
        assert!(matches!(result, Err(PassportError::NotFound(_))));
    }

    #[tokio::test]
    async fn rotate_key_replaces_live_passport() {
        let store = MemoryPassportStore::new();
        let agent_id = AgentId::new();
        let p1 = signed_passport(agent_id).await;
        store.register(p1.clone()).await.unwrap();

        let p2 = signed_passport(agent_id).await;
        // p2 has a fresh signing key — same agent_id, new public key.
        assert_ne!(p1.agent_public_key, p2.agent_public_key);

        store.rotate_key(p2.clone()).await.unwrap();
        let fetched = store.lookup(&agent_id).await.unwrap().unwrap();
        assert_eq!(fetched.agent_public_key, p2.agent_public_key);
    }

    #[tokio::test]
    async fn rotate_unknown_fails() {
        let store = MemoryPassportStore::new();
        let p = signed_passport(AgentId::new()).await;
        let result = store.rotate_key(p).await;
        assert!(matches!(result, Err(PassportError::NotFound(_))));
    }

    #[tokio::test]
    async fn register_rejects_tampered_passport() {
        let store = MemoryPassportStore::new();
        let agent_id = AgentId::new();
        let mut p = signed_passport(agent_id).await;
        p.owner = "tampered".into(); // breaks the self-signature
        let result = store.register(p).await;
        assert!(matches!(result, Err(PassportError::SelfSignatureInvalid)));
    }

    #[tokio::test]
    async fn count_reflects_registrations() {
        let store = MemoryPassportStore::new();
        assert_eq!(store.count().await.unwrap(), 0);
        for _ in 0..3 {
            store
                .register(signed_passport(AgentId::new()).await)
                .await
                .unwrap();
        }
        assert_eq!(store.count().await.unwrap(), 3);
    }
}
