//! [`MemoryStore`] — in-memory reference implementation of [`ReceiptStore`].
//!
//! Used by tests, by the conformance harness as a baseline, and by the
//! embedded-quickstart path. Not for production: no durability, no
//! cross-process visibility.
//!
//! Conformance: implements **Core** and partial **Full** behaviors. Range
//! queries by time/agent/action are implemented; bulk export and sealing
//! are not (Verifiable lives in `backends/walrus-receipt`).

use crate::error::{ReceiptError, Result};
use crate::passport::PassportResolver;
use crate::query::{AppendOptions, Page, Query};
use crate::receipt::Receipt;
use crate::seal::SealStatus;
use crate::signing::SignatureRole;
use crate::store::{AppendKind, AppendOutcome, ReceiptStore};
use crate::verify::verify_receipt_signatures;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use yutha_core::{Hash, PublicKey};
use yutha_crypto::canonical::content_address;

/// In-memory reference receipt store.
///
/// Thread-safe via `tokio::sync::RwLock`. Cloneable handles share state
/// (`Arc` inside).
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    inner: Arc<RwLock<MemoryStoreInner>>,
}

#[derive(Debug, Default)]
struct MemoryStoreInner {
    by_id: HashMap<Hash, Receipt>,
    /// predecessor_hash → list of receipts that depend on it
    by_predecessor: HashMap<Hash, Vec<Hash>>,
}

impl MemoryStore {
    /// New empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ReceiptStore for MemoryStore {
    async fn append(
        &self,
        receipt: Receipt,
        _options: AppendOptions,
        resolver: &dyn PassportResolver,
    ) -> Result<AppendOutcome> {
        // Resolve the actor's public key. Missing → ActorNotResolvable.
        let actor_pk = resolver
            .resolve_actor(&receipt.actor)
            .await?
            .ok_or(ReceiptError::ActorNotResolvable(receipt.actor))?;

        // Pre-resolve any non-actor role keys present on this receipt. Async
        // lookups happen here so the synchronous verify path can close over
        // the cached results below.
        let mut role_keys: HashMap<(SignatureRole, Vec<u8>), PublicKey> = HashMap::new();
        for sig in &receipt.signatures {
            if sig.role == SignatureRole::Actor {
                continue;
            }
            if let Some(pk) = resolver
                .resolve_role(sig.role, &sig.signature.key_fingerprint)
                .await?
            {
                role_keys.insert((sig.role, sig.signature.key_fingerprint.clone()), pk);
            }
        }

        // Verify signatures (canonical-order enforcement happens inside).
        verify_receipt_signatures(&receipt, &actor_pk, |role, fingerprint| {
            role_keys.get(&(role, fingerprint.to_vec())).cloned()
        })?;

        // Content-address.
        let id = content_address(&receipt).map_err(ReceiptError::Crypto)?;

        let mut guard = self.inner.write().await;

        // Idempotency: if the same content-address is already present, return
        // the existing entry.
        if guard.by_id.contains_key(&id) {
            return Ok(AppendOutcome {
                receipt_id: id,
                kind: AppendKind::AlreadyPresent,
                seal: SealStatus::unsealed(),
            });
        }

        // Index causal predecessors.
        for predecessor in &receipt.causal.predecessors {
            guard
                .by_predecessor
                .entry(predecessor.clone())
                .or_default()
                .push(id.clone());
        }

        guard.by_id.insert(id.clone(), receipt);

        Ok(AppendOutcome {
            receipt_id: id,
            kind: AppendKind::Inserted,
            seal: SealStatus::unsealed(),
        })
    }

    async fn get(&self, id: &Hash) -> Result<Option<Receipt>> {
        let guard = self.inner.read().await;
        Ok(guard.by_id.get(id).cloned())
    }

    async fn query(&self, query: Query, _page_token: Option<Vec<u8>>) -> Result<Page> {
        let guard = self.inner.read().await;
        let receipts = match query {
            Query::ByReceiptId(id) => guard.by_id.get(&id).cloned().into_iter().collect(),
            Query::ByPredecessor(p) => guard
                .by_predecessor
                .get(&p.predecessor)
                .map(|ids| {
                    ids.iter()
                        .filter_map(|id| guard.by_id.get(id).cloned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            Query::ByAgent(q) => guard
                .by_id
                .values()
                .filter(|r| r.actor == q.agent_id)
                .cloned()
                .collect(),
            Query::ByActionKind(q) => guard
                .by_id
                .values()
                .filter(|r| r.action_kind == q.action_kind)
                .cloned()
                .collect(),
            Query::ByTimeRange(q) => guard
                .by_id
                .values()
                .filter(|r| {
                    r.occurred_at.monotonic_ns >= q.from.monotonic_ns
                        && r.occurred_at.monotonic_ns <= q.to.monotonic_ns
                })
                .cloned()
                .collect(),
        };
        Ok(Page {
            receipts,
            next_page_token: None,
        })
    }

    async fn count(&self) -> Result<u64> {
        let guard = self.inner.read().await;
        Ok(guard.by_id.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use crate::passport::StaticPassportResolver;
    use crate::query::{ActionKindQuery, AgentQuery, PredecessorQuery};
    use crate::signing::{SignatureRole, SignedBy};
    use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
    use yutha_crypto::canonical::Canonical;
    use yutha_crypto::sign::generate_keypair;

    /// Test fixture: a fresh keypair, a signed receipt produced with it, and
    /// the public key needed to build a resolver. Returning the public key
    /// lets each test build its own resolver from one or more fixtures.
    struct SignedFixture {
        receipt: Receipt,
        public_key: PublicKey,
    }

    fn signed_receipt(actor: AgentId, action: &str, predecessors: Vec<Hash>) -> SignedFixture {
        let key = generate_keypair();
        let mut r = Receipt::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::new())
            .actor(actor)
            .action_kind(action)
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::now())
            .causal(CausalRef::from_iter(predecessors))
            .evidence(Evidence::new("k", "type.yutha.dev/v1/Bytes", b"v".to_vec()))
            .build()
            .unwrap();
        let bytes = r.canonical_bytes().unwrap();
        let sig = key.sign_message(&bytes);
        r.signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
        SignedFixture {
            receipt: r,
            public_key: key.public(),
        }
    }

    /// Build a one-actor resolver matching the supplied fixture.
    fn resolver_for(actor: AgentId, fixture: &SignedFixture) -> StaticPassportResolver {
        StaticPassportResolver::new().with_actor(actor, fixture.public_key.clone())
    }

    #[tokio::test]
    async fn append_then_get() {
        let store = MemoryStore::new();
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);
        let receipt = f.receipt.clone();

        let out = store
            .append(f.receipt, AppendOptions::default(), &resolver)
            .await
            .unwrap();
        assert_eq!(out.kind, AppendKind::Inserted);

        let fetched = store.get(&out.receipt_id).await.unwrap();
        assert_eq!(fetched, Some(receipt));
    }

    #[tokio::test]
    async fn append_is_idempotent() {
        let store = MemoryStore::new();
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);

        let out1 = store
            .append(f.receipt.clone(), AppendOptions::default(), &resolver)
            .await
            .unwrap();
        let out2 = store
            .append(f.receipt.clone(), AppendOptions::default(), &resolver)
            .await
            .unwrap();
        assert_eq!(out1.receipt_id, out2.receipt_id);
        assert_eq!(out2.kind, AppendKind::AlreadyPresent);
        assert_eq!(store.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn lookup_unknown_returns_none() {
        let store = MemoryStore::new();
        let f = signed_receipt(AgentId::new(), "envelope.send", vec![]);
        let bytes = f.receipt.canonical_bytes().unwrap();
        let id = yutha_crypto::sha256(&bytes);
        // Did not append; should be None.
        assert!(store.get(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn predecessor_index_is_populated() {
        let store = MemoryStore::new();
        let parent_actor = AgentId::new();
        let parent_f = signed_receipt(parent_actor, "envelope.send", vec![]);

        let child_actor = AgentId::new();
        // We don't know parent_id yet — append parent first, then build the
        // child fixture with the parent's content-address.
        let resolver_parent = resolver_for(parent_actor, &parent_f);
        let parent_id = store
            .append(
                parent_f.receipt.clone(),
                AppendOptions::default(),
                &resolver_parent,
            )
            .await
            .unwrap()
            .receipt_id;

        let child_f = signed_receipt(child_actor, "envelope.deliver", vec![parent_id.clone()]);
        let resolver = StaticPassportResolver::new()
            .with_actor(parent_actor, parent_f.public_key.clone())
            .with_actor(child_actor, child_f.public_key.clone());
        let _child_id = store
            .append(child_f.receipt.clone(), AppendOptions::default(), &resolver)
            .await
            .unwrap();

        let page = store
            .query(
                Query::ByPredecessor(PredecessorQuery {
                    predecessor: parent_id,
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(page.receipts.len(), 1);
        assert_eq!(page.receipts[0].action_kind, "envelope.deliver");
    }

    #[tokio::test]
    async fn query_by_agent() {
        // Note: each call to `signed_receipt` generates a fresh keypair, so
        // each receipt has a distinct public key even when the actor AgentId
        // repeats. We build a per-append resolver to keep the test simple.
        let store = MemoryStore::new();
        let alice = AgentId::new();
        let bob = AgentId::new();

        for (actor, action) in [(alice, "x"), (alice, "y"), (bob, "z")] {
            let f = signed_receipt(actor, action, vec![]);
            store
                .append(
                    f.receipt,
                    AppendOptions::default(),
                    &StaticPassportResolver::new().with_actor(actor, f.public_key),
                )
                .await
                .unwrap();
        }

        let alice_page = store
            .query(Query::ByAgent(AgentQuery { agent_id: alice }), None)
            .await
            .unwrap();
        assert_eq!(alice_page.receipts.len(), 2);

        let bob_page = store
            .query(Query::ByAgent(AgentQuery { agent_id: bob }), None)
            .await
            .unwrap();
        assert_eq!(bob_page.receipts.len(), 1);
    }

    #[tokio::test]
    async fn query_by_action_kind() {
        let store = MemoryStore::new();
        let actor1 = AgentId::new();
        let f1 = signed_receipt(actor1, "envelope.send", vec![]);
        let actor2 = AgentId::new();
        let f2 = signed_receipt(actor2, "agent.register", vec![]);

        // Bind resolvers first so the &f borrow doesn't race the f.receipt
        // move in the same argument list.
        let r1 = resolver_for(actor1, &f1);
        let r2 = resolver_for(actor2, &f2);
        store
            .append(f1.receipt, AppendOptions::default(), &r1)
            .await
            .unwrap();
        store
            .append(f2.receipt, AppendOptions::default(), &r2)
            .await
            .unwrap();

        let send_page = store
            .query(
                Query::ByActionKind(ActionKindQuery {
                    action_kind: "envelope.send".into(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(send_page.receipts.len(), 1);
    }

    #[tokio::test]
    async fn count_reflects_appends() {
        let store = MemoryStore::new();
        assert_eq!(store.count().await.unwrap(), 0);
        let actor = AgentId::new();
        let f = signed_receipt(actor, "x", vec![]);
        let r = resolver_for(actor, &f);
        store
            .append(f.receipt, AppendOptions::default(), &r)
            .await
            .unwrap();
        assert_eq!(store.count().await.unwrap(), 1);
    }

    // New tests covering the append-verifies policy.

    #[tokio::test]
    async fn append_rejects_unsigned_receipt() {
        let store = MemoryStore::new();
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);

        // Strip the actor signature.
        let mut r = f.receipt;
        r.signatures.clear();

        let result = store.append(r, AppendOptions::default(), &resolver).await;
        assert!(matches!(
            result,
            Err(crate::ReceiptError::MissingSignatureRole {
                role: SignatureRole::Actor
            })
        ));
    }

    #[tokio::test]
    async fn append_rejects_tampered_actor_signature() {
        let store = MemoryStore::new();
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);

        // Tamper with a field after signing — content changed, signature now
        // verifies over different bytes.
        let mut r = f.receipt;
        r.action_kind = "tampered".into();

        let result = store.append(r, AppendOptions::default(), &resolver).await;
        assert!(
            matches!(result, Err(crate::ReceiptError::SignatureFailed { .. })),
            "expected SignatureFailed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn append_rejects_unknown_actor() {
        let store = MemoryStore::new();
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        // Empty resolver — the actor is unknown.
        let resolver = StaticPassportResolver::new();

        let result = store
            .append(f.receipt, AppendOptions::default(), &resolver)
            .await;
        assert!(
            matches!(result, Err(crate::ReceiptError::ActorNotResolvable(a)) if a == actor),
            "expected ActorNotResolvable, got {result:?}"
        );
    }
}
