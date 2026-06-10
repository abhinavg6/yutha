//! Append-only, content-addressed, signed receipts. The load-bearing wall.
//!
//! Per build-plan.md §4.1, this crate is built before everything else that
//! emits receipts. Per [`/spec/receipt/receipt-v1.proto`](../../../spec/receipt/receipt-v1.proto)
//! and its rationale, behavior is normative.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod error;
pub mod evidence;
pub mod memory;
pub mod merkle;
pub mod passport;
pub mod preimage;
pub mod proto_conv;
pub mod query;
pub mod receipt;
pub mod replay_store;
pub mod seal;
pub mod sealer;
pub mod signing;
pub mod store;
pub mod verify;

pub use error::{ReceiptError, Result};
pub use evidence::Evidence;
pub use memory::MemoryStore;
pub use merkle::{build_merkle, sorted_pair_hash, verify_path, LeafProof, MerkleBatch};
pub use passport::{PassportResolver, StaticPassportResolver};
pub use preimage::{canonical_preimage, MAX_ACTION_KIND_LEN};
pub use query::{
    ActionKindQuery, AgentQuery, AppendOptions, Page, PredecessorQuery, Query, TimeRangeQuery,
};
pub use receipt::{Receipt, ReceiptBuilder};
pub use replay_store::{
    MemoryReplayStore, ReplayMode, ReplaySessionId, ReplaySessionMetadata, ReplaySessionWindow,
    ReplayStore,
};
pub use seal::{SealState, SealStatus};
pub use sealer::{
    compute_histogram, compute_ns_range, LocalSealer, SealError, SealedBatch, Sealer,
};
pub use signing::{SignatureRole, SignedBy};
pub use store::{AppendKind, AppendOutcome, ReceiptStore, SealStore};
pub use verify::{verify_receipt_signatures, VerificationOutcome};
