//! `PublishingReceiptStore` — `ReceiptStore` decorator that fans
//! every appended receipt out to an mpsc channel for the enforcement
//! engine (F9 / RFC 0013) to subscribe to.
//!
//! ## Design
//!
//! Per the F10 design decision (see the saved feedback memory): receipt
//! subscription uses an **async channel** rather than a sync hook in
//! the append path. ReceiptStore::append still does its full
//! signature-verification + persistence work synchronously; on success
//! it `try_send`s a snapshot of the receipt's match-relevant fields
//! onto the channel and returns. A separate background task drains
//! the channel and calls
//! [`yutha_cedar_plus::EnforcementEngine::on_receipt`].
//!
//! Backpressure: on a full channel the publisher logs and drops. The
//! receipt log itself is authoritative — the engine's state is
//! reconstructable from the log per evaluation.md §6, so dropped
//! notifications cost a future cold-start rebuild, not correctness.
//!
//! ## Subject extraction
//!
//! The enforcement engine needs the **subject** agent — the agent whose
//! action the receipt describes — not the actor (which for constitution-
//! layer receipts is the control plane itself). The publisher walks the
//! receipt's evidence looking for a `subject_agent_id` field; if absent
//! it falls back to the actor's agent_id (which is correct for
//! substrate-emitter receipts like `capability.check.*` where the
//! subject *is* the actor).

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::warn;
use yutha_cedar_plus::Score;
use yutha_core::Hash;
use yutha_receipt::{
    AppendOptions, AppendOutcome, Page, PassportResolver, Query, Receipt, ReceiptStore,
    Result as ReceiptResult,
};

/// Owned snapshot of a receipt's match-relevant fields. Sent across
/// the publisher channel; consumed by the enforcement-engine
/// forwarder task.
///
/// Equivalent to `yutha_cedar_plus::ReceiptView` but owned (no
/// borrowed-from-store lifetimes). The forwarder converts an owned
/// `EnforcementReceiptView` into a borrowed `ReceiptView` for the
/// engine call.
#[derive(Debug, Clone)]
pub struct EnforcementReceiptView {
    pub action_kind: String,
    pub principal_id: Option<String>,
    pub deny_reason: Option<String>,
    pub forbid_rule_id: Option<String>,
    pub occurred_at_unix_ns: u64,
    pub occurred_at_wall_clock: String,
    pub reputation_delta: Option<Score>,
}

/// Channel capacity. Sized generously so a typical send burst doesn't
/// drop; on full, [`PublishingReceiptStore::append`] logs and drops
/// the notification (the receipt itself still landed in the inner
/// store).
pub const PUBLISH_CHANNEL_CAPACITY: usize = 4096;

/// Wraps an existing `ReceiptStore` and broadcasts every successful
/// append onto an mpsc channel. Existing call sites that go through
/// the `ReceiptStore` trait pick up the publishing behaviour
/// automatically — no per-callsite change needed.
pub struct PublishingReceiptStore {
    inner: Arc<dyn ReceiptStore>,
    tx: mpsc::Sender<EnforcementReceiptView>,
}

impl PublishingReceiptStore {
    /// Construct a publisher wrapping the given inner store. The
    /// returned `(Arc<Self>, Receiver)` pair has the receiver end
    /// drained by the F10f background task; the Arc<Self> goes into
    /// `ControlPlaneState.receipt_store` (where it satisfies the
    /// existing `Arc<dyn ReceiptStore>` field via trait coercion).
    pub fn new(
        inner: Arc<dyn ReceiptStore>,
    ) -> (Arc<Self>, mpsc::Receiver<EnforcementReceiptView>) {
        let (tx, rx) = mpsc::channel(PUBLISH_CHANNEL_CAPACITY);
        (Arc::new(Self { inner, tx }), rx)
    }
}

#[async_trait]
impl ReceiptStore for PublishingReceiptStore {
    async fn append(
        &self,
        receipt: Receipt,
        options: AppendOptions,
        resolver: &dyn PassportResolver,
    ) -> ReceiptResult<AppendOutcome> {
        // Build the snapshot BEFORE the move into append — the inner
        // call consumes `receipt`.
        let view = build_view(&receipt);

        let outcome = self.inner.append(receipt, options, resolver).await?;

        // Non-blocking send; on full channel, the engine misses this
        // receipt but the log holds it for cold-start replay.
        if let Err(e) = self.tx.try_send(view) {
            warn!(
                error = %e,
                "PublishingReceiptStore channel full or closed; enforcement engine \
                 will rebuild from the receipt log on next consistency pass",
            );
        }

        Ok(outcome)
    }

    async fn get(&self, id: &Hash) -> ReceiptResult<Option<Receipt>> {
        self.inner.get(id).await
    }

    async fn query(&self, query: Query, page_token: Option<Vec<u8>>) -> ReceiptResult<Page> {
        self.inner.query(query, page_token).await
    }

    async fn count(&self) -> ReceiptResult<u64> {
        self.inner.count().await
    }
}

/// Extract the enforcement-relevant subset of a receipt's content.
///
/// The subject is taken from a `subject_agent_id` evidence field when
/// present (added by control-plane-emitted receipts like
/// `constitution.evaluate.*`); otherwise falls back to the actor's
/// AgentId stringified (the right answer for substrate-emitter
/// receipts where the subject == actor).
fn build_view(receipt: &Receipt) -> EnforcementReceiptView {
    let mut principal_id: Option<String> = None;
    let mut deny_reason: Option<String> = None;
    let mut forbid_rule_id: Option<String> = None;
    let mut reputation_delta: Option<Score> = None;

    for ev in &receipt.evidence {
        match ev.key.as_str() {
            "subject_agent_id" | "target_agent_id" if principal_id.is_none() => {
                principal_id = String::from_utf8(ev.value.clone()).ok();
            }
            "deny_reason" => {
                deny_reason = String::from_utf8(ev.value.clone()).ok();
            }
            "forbid_rule_id" => {
                forbid_rule_id = String::from_utf8(ev.value.clone()).ok();
            }
            "reputation_delta" => {
                if let Ok(s) = String::from_utf8(ev.value.clone()) {
                    reputation_delta = Some(Score(s));
                }
            }
            _ => {}
        }
    }
    // Fallback: when no subject evidence is present, use the actor.
    if principal_id.is_none() {
        principal_id = Some(receipt.actor.to_string());
    }

    EnforcementReceiptView {
        action_kind: receipt.action_kind.clone(),
        principal_id,
        deny_reason,
        forbid_rule_id,
        occurred_at_unix_ns: receipt.occurred_at.monotonic_ns,
        occurred_at_wall_clock: receipt.occurred_at.wall_clock.clone(),
        reputation_delta,
    }
}
