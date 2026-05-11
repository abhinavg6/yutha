//! Receipt-store conformance suite.
//!
//! Implements the Core-tier checks from
//! [`/docs/conformance/conformance-suite.md`](../../../docs/conformance/conformance-suite.md) §3.3.
//! Backends pass a factory; the suite runs against a freshly-constructed
//! store per test.
//!
//! Every test that appends a receipt now passes a [`StaticPassportResolver`]
//! to satisfy the verify-on-append policy (see `ReceiptStore::append`
//! contract). The resolver is fixture-scoped, not backend-scoped — backends
//! provide stores; the suite produces the resolver per test.

use crate::outcome::{Outcome, TestOutcome};
use std::sync::Arc;
use yutha_core::{AgentId, CausalRef, Hash, PublicKey, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::{content_address, Canonical};
use yutha_crypto::sign::generate_keypair;
use yutha_receipt::{
    AppendOptions, Evidence, PredecessorQuery, Query, Receipt, ReceiptError, ReceiptStore,
    SignatureRole, SignedBy, StaticPassportResolver,
};

/// A factory that builds a fresh `ReceiptStore` for each test.
///
/// Boxed and dynamically dispatched so backends can be plugged in without
/// generic ceremony.
pub type StoreFactory =
    Box<dyn Fn() -> futures::future::BoxFuture<'static, Arc<dyn ReceiptStore>> + Send + Sync>;

/// A reloader that simulates a process restart against the *same* persistent
/// backing state — same Postgres pool, same Walrus namespace, same disk
/// directory. Receives the current store handle and returns a fresh handle
/// over the same state.
///
/// Backends without durable persistence (e.g., in-memory) leave this `None`;
/// the durability test is then skipped. Backends with persistence MUST
/// provide a reloader for their conformance claim to cover the Core
/// "sequential append durable across process restart" requirement.
pub type StoreReloader = Box<
    dyn Fn(Arc<dyn ReceiptStore>) -> futures::future::BoxFuture<'static, Arc<dyn ReceiptStore>>
        + Send
        + Sync,
>;

/// Conformance suite for `ReceiptStore` implementations at the Core tier.
pub struct ReceiptStoreSuite {
    factory: StoreFactory,
    reloader: Option<StoreReloader>,
}

impl ReceiptStoreSuite {
    /// Construct a new suite with a store factory.
    pub fn new(factory: StoreFactory) -> Self {
        Self {
            factory,
            reloader: None,
        }
    }

    /// Attach a reloader so the durability-across-restart test can actually
    /// exercise the backend. Without this, that test is skipped.
    pub fn with_reloader(mut self, reloader: StoreReloader) -> Self {
        self.reloader = Some(reloader);
        self
    }

    /// Run every test in the suite. Returns the aggregate outcome.
    pub async fn run(&self) -> Outcome {
        let mut outcome = Outcome::default();
        outcome.record(self.test_append_then_get().await);
        outcome.record(self.test_idempotent_append().await);
        outcome.record(self.test_get_unknown_returns_none().await);
        outcome.record(self.test_predecessor_index().await);
        outcome.record(self.test_content_address_consistency().await);
        outcome.record(self.test_count_reflects_appends().await);
        // Verify-on-append policy tests.
        outcome.record(self.test_append_rejects_unsigned().await);
        outcome.record(self.test_append_rejects_tampered_signature().await);
        outcome.record(self.test_append_rejects_unknown_actor().await);
        // Core requirements from conformance-suite.md §3.3 that need
        // multi-step or capability-gated coverage.
        outcome.record(
            self.test_concurrent_appends_preserve_causal_ordering()
                .await,
        );
        outcome.record(self.test_durable_across_restart().await);
        outcome
    }

    // -------------------------------------------------------------------
    // Tests — existing
    // -------------------------------------------------------------------

    async fn test_append_then_get(&self) -> TestOutcome {
        let store = (self.factory)().await;
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);
        let receipt = f.receipt.clone();
        match store
            .append(f.receipt, AppendOptions::default(), &resolver)
            .await
        {
            Ok(out) => match store.get(&out.receipt_id).await {
                Ok(Some(fetched)) if fetched == receipt => {
                    TestOutcome::pass("receipt.append_then_get")
                }
                Ok(Some(_)) => TestOutcome::fail(
                    "receipt.append_then_get",
                    "fetched receipt did not equal appended",
                ),
                Ok(None) => {
                    TestOutcome::fail("receipt.append_then_get", "fetched None after append")
                }
                Err(e) => TestOutcome::fail("receipt.append_then_get", format!("get errored: {e}")),
            },
            Err(e) => TestOutcome::fail("receipt.append_then_get", format!("append errored: {e}")),
        }
    }

    async fn test_idempotent_append(&self) -> TestOutcome {
        let store = (self.factory)().await;
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);
        let r = f.receipt.clone();
        let out1 = match store
            .append(r.clone(), AppendOptions::default(), &resolver)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                return TestOutcome::fail("receipt.idempotent_append", format!("first append: {e}"))
            }
        };
        let out2 = match store.append(r, AppendOptions::default(), &resolver).await {
            Ok(o) => o,
            Err(e) => {
                return TestOutcome::fail(
                    "receipt.idempotent_append",
                    format!("second append: {e}"),
                )
            }
        };
        if out1.receipt_id != out2.receipt_id {
            return TestOutcome::fail(
                "receipt.idempotent_append",
                "second append returned a different content-address",
            );
        }
        match store.count().await {
            Ok(1) => TestOutcome::pass("receipt.idempotent_append"),
            Ok(c) => TestOutcome::fail(
                "receipt.idempotent_append",
                format!("expected count 1 after idempotent reappend, got {c}"),
            ),
            Err(e) => TestOutcome::fail("receipt.idempotent_append", format!("count: {e}")),
        }
    }

    async fn test_get_unknown_returns_none(&self) -> TestOutcome {
        let store = (self.factory)().await;
        let f = signed_receipt(AgentId::new(), "envelope.send", vec![]);
        let bytes = match f.receipt.canonical_bytes() {
            Ok(b) => b,
            Err(e) => {
                return TestOutcome::fail(
                    "receipt.get_unknown_returns_none",
                    format!("canonical bytes: {e}"),
                )
            }
        };
        let id = yutha_crypto::sha256(&bytes);
        match store.get(&id).await {
            Ok(None) => TestOutcome::pass("receipt.get_unknown_returns_none"),
            Ok(Some(_)) => TestOutcome::fail(
                "receipt.get_unknown_returns_none",
                "expected None for unknown id",
            ),
            Err(e) => TestOutcome::fail(
                "receipt.get_unknown_returns_none",
                format!("get errored: {e}"),
            ),
        }
    }

    async fn test_predecessor_index(&self) -> TestOutcome {
        let store = (self.factory)().await;

        let parent_actor = AgentId::new();
        let parent_f = signed_receipt(parent_actor, "envelope.send", vec![]);
        let parent_resolver = resolver_for(parent_actor, &parent_f);
        let parent_id = match store
            .append(
                parent_f.receipt.clone(),
                AppendOptions::default(),
                &parent_resolver,
            )
            .await
        {
            Ok(o) => o.receipt_id,
            Err(e) => {
                return TestOutcome::fail(
                    "receipt.predecessor_index",
                    format!("parent append: {e}"),
                )
            }
        };

        let child_actor = AgentId::new();
        let child_f = signed_receipt(child_actor, "envelope.deliver", vec![parent_id.clone()]);
        // Build a resolver that knows both actors so the child append's
        // verification step (which checks the child's actor signature) can
        // succeed.
        let resolver = StaticPassportResolver::new()
            .with_actor(parent_actor, parent_f.public_key.clone())
            .with_actor(child_actor, child_f.public_key.clone());
        if let Err(e) = store
            .append(child_f.receipt, AppendOptions::default(), &resolver)
            .await
        {
            return TestOutcome::fail("receipt.predecessor_index", format!("child append: {e}"));
        }
        match store
            .query(
                Query::ByPredecessor(PredecessorQuery {
                    predecessor: parent_id,
                }),
                None,
            )
            .await
        {
            Ok(page) if page.receipts.len() == 1 => TestOutcome::pass("receipt.predecessor_index"),
            Ok(page) => TestOutcome::fail(
                "receipt.predecessor_index",
                format!(
                    "expected 1 child via predecessor query, got {}",
                    page.receipts.len()
                ),
            ),
            Err(e) => TestOutcome::fail("receipt.predecessor_index", format!("query: {e}")),
        }
    }

    async fn test_content_address_consistency(&self) -> TestOutcome {
        let store = (self.factory)().await;
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);
        let expected = match content_address(&f.receipt) {
            Ok(h) => h,
            Err(e) => {
                return TestOutcome::fail(
                    "receipt.content_address_consistency",
                    format!("compute address: {e}"),
                )
            }
        };
        match store
            .append(f.receipt, AppendOptions::default(), &resolver)
            .await
        {
            Ok(out) if out.receipt_id == expected => {
                TestOutcome::pass("receipt.content_address_consistency")
            }
            Ok(out) => TestOutcome::fail(
                "receipt.content_address_consistency",
                format!(
                    "store returned different content-address.\nclient computed: {expected}\nstore returned: {}",
                    out.receipt_id
                ),
            ),
            Err(e) => TestOutcome::fail(
                "receipt.content_address_consistency",
                format!("append: {e}"),
            ),
        }
    }

    async fn test_count_reflects_appends(&self) -> TestOutcome {
        let store = (self.factory)().await;
        let initial = match store.count().await {
            Ok(c) => c,
            Err(e) => {
                return TestOutcome::fail(
                    "receipt.count_reflects_appends",
                    format!("initial count: {e}"),
                )
            }
        };
        if initial != 0 {
            return TestOutcome::fail(
                "receipt.count_reflects_appends",
                format!("expected fresh store empty, got {initial}"),
            );
        }
        for i in 0..5 {
            let actor = AgentId::new();
            let f = signed_receipt(actor, "envelope.send", vec![]);
            let resolver = resolver_for(actor, &f);
            if let Err(e) = store
                .append(f.receipt, AppendOptions::default(), &resolver)
                .await
            {
                return TestOutcome::fail(
                    "receipt.count_reflects_appends",
                    format!("append {i}: {e}"),
                );
            }
        }
        match store.count().await {
            Ok(5) => TestOutcome::pass("receipt.count_reflects_appends"),
            Ok(c) => TestOutcome::fail(
                "receipt.count_reflects_appends",
                format!("expected 5, got {c}"),
            ),
            Err(e) => TestOutcome::fail(
                "receipt.count_reflects_appends",
                format!("final count: {e}"),
            ),
        }
    }

    // -------------------------------------------------------------------
    // Tests — verify-on-append policy
    // -------------------------------------------------------------------

    async fn test_append_rejects_unsigned(&self) -> TestOutcome {
        let store = (self.factory)().await;
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);

        let mut r = f.receipt;
        r.signatures.clear();

        match store.append(r, AppendOptions::default(), &resolver).await {
            Err(ReceiptError::MissingSignatureRole {
                role: SignatureRole::Actor,
            }) => TestOutcome::pass("receipt.append_rejects_unsigned"),
            Err(e) => TestOutcome::fail(
                "receipt.append_rejects_unsigned",
                format!("expected MissingSignatureRole(Actor), got {e:?}"),
            ),
            Ok(_) => TestOutcome::fail(
                "receipt.append_rejects_unsigned",
                "expected reject; append succeeded",
            ),
        }
    }

    async fn test_append_rejects_tampered_signature(&self) -> TestOutcome {
        let store = (self.factory)().await;
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);

        // Mutate a signed field; signature now verifies over different bytes.
        let mut r = f.receipt;
        r.action_kind = "tampered".into();

        match store.append(r, AppendOptions::default(), &resolver).await {
            Err(ReceiptError::SignatureFailed { .. }) => {
                TestOutcome::pass("receipt.append_rejects_tampered_signature")
            }
            Err(e) => TestOutcome::fail(
                "receipt.append_rejects_tampered_signature",
                format!("expected SignatureFailed, got {e:?}"),
            ),
            Ok(_) => TestOutcome::fail(
                "receipt.append_rejects_tampered_signature",
                "expected reject; append succeeded",
            ),
        }
    }

    async fn test_append_rejects_unknown_actor(&self) -> TestOutcome {
        let store = (self.factory)().await;
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        // Empty resolver — the actor isn't registered.
        let resolver = StaticPassportResolver::new();

        match store
            .append(f.receipt, AppendOptions::default(), &resolver)
            .await
        {
            Err(ReceiptError::ActorNotResolvable(returned)) if returned == actor => {
                TestOutcome::pass("receipt.append_rejects_unknown_actor")
            }
            Err(ReceiptError::ActorNotResolvable(returned)) => TestOutcome::fail(
                "receipt.append_rejects_unknown_actor",
                format!("ActorNotResolvable returned wrong agent: {returned}"),
            ),
            Err(e) => TestOutcome::fail(
                "receipt.append_rejects_unknown_actor",
                format!("expected ActorNotResolvable, got {e:?}"),
            ),
            Ok(_) => TestOutcome::fail(
                "receipt.append_rejects_unknown_actor",
                "expected reject; append succeeded",
            ),
        }
    }

    // -------------------------------------------------------------------
    // Tests — multi-step / capability-gated
    // -------------------------------------------------------------------

    /// Concurrent appends of N children pointing at a shared parent must
    /// preserve every causal pointer; the predecessor query must return all
    /// N children. Catches lock-contention drops, lost updates on the
    /// predecessor index, and any racy interleaving that would let a child
    /// commit without its causal edge.
    async fn test_concurrent_appends_preserve_causal_ordering(&self) -> TestOutcome {
        const NAME: &str = "receipt.concurrent_appends_preserve_causal_ordering";
        const CHILDREN: usize = 10;

        let store = (self.factory)().await;

        // 1) Append the shared parent first; we need its content-address
        //    before the children can reference it.
        let parent_actor = AgentId::new();
        let parent_f = signed_receipt(parent_actor, "envelope.send", vec![]);
        let parent_resolver = resolver_for(parent_actor, &parent_f);
        let parent_id = match store
            .append(
                parent_f.receipt.clone(),
                AppendOptions::default(),
                &parent_resolver,
            )
            .await
        {
            Ok(o) => o.receipt_id,
            Err(e) => return TestOutcome::fail(NAME, format!("parent append: {e}")),
        };

        // 2) Build N children up front, each with a fresh keypair and the
        //    shared parent as their sole causal predecessor. Each child
        //    has unique content (distinct actor + timestamp), so distinct
        //    content-addresses — none should be deduplicated.
        let mut children = Vec::with_capacity(CHILDREN);
        let mut resolver =
            StaticPassportResolver::new().with_actor(parent_actor, parent_f.public_key.clone());
        for _ in 0..CHILDREN {
            let actor = AgentId::new();
            let f = signed_receipt(actor, "envelope.deliver", vec![parent_id.clone()]);
            resolver = resolver.with_actor(actor, f.public_key.clone());
            children.push(f.receipt);
        }
        let resolver = Arc::new(resolver);

        // 3) Append every child concurrently, then await all.
        let mut handles = Vec::with_capacity(CHILDREN);
        for child in children {
            let store = store.clone();
            let resolver = resolver.clone();
            handles.push(tokio::spawn(async move {
                store
                    .append(child, AppendOptions::default(), resolver.as_ref())
                    .await
            }));
        }
        for (i, h) in handles.into_iter().enumerate() {
            match h.await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return TestOutcome::fail(NAME, format!("child {i} append: {e}")),
                Err(e) => return TestOutcome::fail(NAME, format!("child {i} task join: {e}")),
            }
        }

        // 4) Predecessor query must enumerate exactly the N children.
        match store
            .query(
                Query::ByPredecessor(PredecessorQuery {
                    predecessor: parent_id,
                }),
                None,
            )
            .await
        {
            Ok(page) if page.receipts.len() == CHILDREN => TestOutcome::pass(NAME),
            Ok(page) => TestOutcome::fail(
                NAME,
                format!(
                    "expected {CHILDREN} children via predecessor query, got {}",
                    page.receipts.len()
                ),
            ),
            Err(e) => TestOutcome::fail(NAME, format!("predecessor query: {e}")),
        }
    }

    /// Sequential append must survive a process restart. The test appends a
    /// receipt, asks the backend to "restart" via the reloader (typically a
    /// fresh client handle against the same Postgres pool / file / Walrus
    /// namespace), then re-reads through the new handle.
    ///
    /// Skipped on backends that don't claim durability (no reloader
    /// configured) — in-memory stores can't satisfy this, and pretending
    /// otherwise would lie about conformance.
    async fn test_durable_across_restart(&self) -> TestOutcome {
        const NAME: &str = "receipt.durable_across_restart";

        let Some(reloader) = self.reloader.as_ref() else {
            return TestOutcome::skip(
                NAME,
                "backend declined durability claim (no reloader provided)",
            );
        };

        let store = (self.factory)().await;
        let actor = AgentId::new();
        let f = signed_receipt(actor, "envelope.send", vec![]);
        let resolver = resolver_for(actor, &f);
        let original = f.receipt.clone();

        let receipt_id = match store
            .append(f.receipt, AppendOptions::default(), &resolver)
            .await
        {
            Ok(o) => o.receipt_id,
            Err(e) => return TestOutcome::fail(NAME, format!("pre-restart append: {e}")),
        };

        // Drop the original handle, then hand the reloader the (last
        // remaining) Arc to do whatever cleanup it cares to. The reloader
        // returns a fresh handle against the same backing state.
        let reloaded = reloader(store).await;

        match reloaded.get(&receipt_id).await {
            Ok(Some(fetched)) if fetched == original => TestOutcome::pass(NAME),
            Ok(Some(_)) => {
                TestOutcome::fail(NAME, "receipt survived restart but its contents changed")
            }
            Ok(None) => TestOutcome::fail(NAME, "receipt did not survive restart (returned None)"),
            Err(e) => TestOutcome::fail(NAME, format!("post-restart get: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn resolver_for(actor: AgentId, fixture: &SignedFixture) -> StaticPassportResolver {
    StaticPassportResolver::new().with_actor(actor, fixture.public_key.clone())
}

#[cfg(test)]
#[cfg(feature = "in-memory-receipt-suite")]
mod in_memory_tests {
    use super::*;
    use yutha_receipt::MemoryStore;

    #[tokio::test]
    async fn in_memory_passes_core_suite() {
        let factory: StoreFactory = Box::new(|| {
            Box::pin(async move { Arc::new(MemoryStore::new()) as Arc<dyn ReceiptStore> })
        });
        let suite = ReceiptStoreSuite::new(factory);
        let outcome = suite.run().await;
        assert!(
            outcome.passed(),
            "in-memory failed conformance: {} failure(s):\n{:#?}",
            outcome.failures(),
            outcome.failed().collect::<Vec<_>>()
        );
    }
}
