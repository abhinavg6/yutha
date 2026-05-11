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
pub mod passport;
pub mod proto_conv;
pub mod query;
pub mod receipt;
pub mod seal;
pub mod signing;
pub mod store;
pub mod verify;

pub use error::{ReceiptError, Result};
pub use evidence::Evidence;
pub use memory::MemoryStore;
pub use passport::{PassportResolver, StaticPassportResolver};
pub use query::{
    ActionKindQuery, AgentQuery, AppendOptions, Page, PredecessorQuery, Query, TimeRangeQuery,
};
pub use receipt::{Receipt, ReceiptBuilder};
pub use seal::{SealState, SealStatus};
pub use signing::{SignatureRole, SignedBy};
pub use store::{AppendKind, AppendOutcome, ReceiptStore};
pub use verify::{verify_receipt_signatures, VerificationOutcome};
