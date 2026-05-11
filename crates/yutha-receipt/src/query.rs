//! Query types for the [`crate::store::ReceiptStore`] interface.
//!
//! Mirrors the `QueryRequest` / `QueryResponse` shapes from
//! [`/spec/receipt/receipt-v1.proto`](../../../spec/receipt/receipt-v1.proto).

use crate::receipt::Receipt;
use yutha_core::{AgentId, Hash, Timestamp};

/// A query against the receipt store.
///
/// Core conformance requires support for [`Query::ByReceiptId`] and
/// [`Query::ByPredecessor`]. Full conformance adds the by-agent / by-action /
/// by-time variants.
#[derive(Debug, Clone)]
pub enum Query {
    /// Look up exactly one receipt by content-address.
    ByReceiptId(Hash),
    /// "Receipts that depend on this predecessor."
    ByPredecessor(PredecessorQuery),
    /// "All receipts with this actor."
    ByAgent(AgentQuery),
    /// "All receipts with this canonical action_kind."
    ByActionKind(ActionKindQuery),
    /// "All receipts within this time window."
    ByTimeRange(TimeRangeQuery),
}

/// "All receipts that have `predecessor` in their causal predecessors."
#[derive(Debug, Clone)]
pub struct PredecessorQuery {
    /// The predecessor receipt hash to filter on.
    pub predecessor: Hash,
}

/// "All receipts with `actor == agent_id`."
#[derive(Debug, Clone)]
pub struct AgentQuery {
    /// The actor to filter on.
    pub agent_id: AgentId,
}

/// "All receipts with `action_kind == kind`."
#[derive(Debug, Clone)]
pub struct ActionKindQuery {
    /// Exact action_kind string. Wildcard support is Full-tier.
    pub action_kind: String,
}

/// "All receipts where `from <= occurred_at <= to`." Comparison uses
/// monotonic_ns where applicable; cross-process queries fall back to
/// wall_clock.
#[derive(Debug, Clone)]
pub struct TimeRangeQuery {
    /// Lower bound (inclusive).
    pub from: Timestamp,
    /// Upper bound (inclusive).
    pub to: Timestamp,
}

/// A page of query results.
#[derive(Debug, Clone)]
pub struct Page {
    /// The receipts in this page.
    pub receipts: Vec<Receipt>,
    /// Token for the next page; None when exhausted.
    pub next_page_token: Option<Vec<u8>>,
}

/// Options when appending a receipt.
#[derive(Debug, Clone, Default)]
pub struct AppendOptions {
    /// If true, the store synchronously waits for the receipt to be sealed
    /// into a Merkle batch before acknowledging. Default false (unsealed
    /// acknowledgement is sufficient and lower-latency).
    pub wait_for_seal: bool,
    /// Optional pagination limit hint (used by some stores; ignored by
    /// in-memory).
    pub page_limit: Option<u32>,
}
