//! [`ReceiptStore`] — the trait every backend implements.
//!
//! Mirrors the Append / Query / Export operations from
//! [`/spec/receipt/receipt-v1.proto`](../../../spec/receipt/receipt-v1.proto).
//! Async; backends that are synchronous internally (e.g., the in-memory
//! reference) wrap their work in `async`.

use crate::error::Result;
use crate::passport::PassportResolver;
use crate::query::{AppendOptions, Page, Query};
use crate::receipt::Receipt;
use async_trait::async_trait;
use yutha_core::Hash;

/// A store of append-only, content-addressed, signed receipts.
///
/// Conformance levels per [`/docs/conformance/conformance-suite.md`](../../../docs/conformance/conformance-suite.md) §3.3:
/// - **Core**: append, lookup by content-address, content-address consistency, tamper detection.
/// - **Full**: range queries by time/agent/action; bulk export with verifiable manifest; durable across restart; concurrent appends.
/// - **Verifiable**: cross-org mutual recognition; selective disclosure; sealing into Merkle batches.
#[async_trait]
pub trait ReceiptStore: Send + Sync {
    /// Append a receipt to the store. Returns the content-address of the
    /// persisted receipt.
    ///
    /// Implementations MUST:
    /// - Recompute the receipt's content-address.
    /// - Resolve the actor's public key via `resolver.resolve_actor`.
    ///   If the resolver returns None,
    ///   [`crate::ReceiptError::ActorNotResolvable`].
    /// - Verify the actor signature against the resolved key. Failure →
    ///   [`crate::ReceiptError::SignatureFailed`].
    /// - Verify any non-actor role signatures whose key the resolver knows.
    ///   Roles whose key the resolver returns None for are skipped (per the
    ///   optional-role policy in [`crate::verify::verify_receipt_signatures`]).
    /// - Enforce canonical signature order
    ///   (Actor → ControlPlane → Supervisor → Attestation → BatchRoot).
    /// - Be idempotent on identical receipts (same canonical bytes →
    ///   returns the existing content-address; no duplicate stored).
    /// - Be append-only (no in-place mutation; mutation attempts return
    ///   [`crate::ReceiptError::AppendOnly`]).
    ///
    /// The `resolver` parameter is a `&dyn` so that backends remain
    /// object-safe; in production this is the passport store's adapter.
    async fn append(
        &self,
        receipt: Receipt,
        options: AppendOptions,
        resolver: &dyn PassportResolver,
    ) -> Result<AppendOutcome>;

    /// Look up a single receipt by content-address.
    async fn get(&self, id: &Hash) -> Result<Option<Receipt>>;

    /// Run a query. Returns a page; callers iterate via `next_page_token`.
    /// Core conformance only requires `Query::ByReceiptId` and
    /// `Query::ByPredecessor` to be implemented; backends that don't yet
    /// support other variants return [`crate::ReceiptError::InvalidQuery`].
    async fn query(&self, query: Query, page_token: Option<Vec<u8>>) -> Result<Page>;

    /// Number of receipts in the store. Cheap on in-memory; backend-specific
    /// otherwise. Useful for testing and for monitoring.
    async fn count(&self) -> Result<u64>;
}

/// Result of an append.
#[derive(Debug, Clone)]
pub struct AppendOutcome {
    /// The content-address of the persisted receipt.
    pub receipt_id: Hash,
    /// Whether this was a fresh append or a return of a pre-existing
    /// idempotent match.
    pub kind: AppendKind,
    /// Sealing state at append time (typically Unsealed unless
    /// `wait_for_seal` was set).
    pub seal: crate::seal::SealStatus,
}

/// Kind of append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendKind {
    /// New receipt added to the store.
    Inserted,
    /// Receipt with identical canonical bytes was already present;
    /// returning that one (idempotent).
    AlreadyPresent,
}
