//! `SuiAnchorClient` trait + value types.
//!
//! The trait is the seam between this crate's domain logic
//! ([`crate::sealer::SuiSealer`], [`crate::driver::AnchorDriver`]) and
//! whichever Sui SDK is doing the actual RPC. Two impls in tree:
//!
//! - [`crate::rpc::RpcAnchorClient`] — production, uses the
//!   modular Sui Rust SDK (sui-rpc + sui-transaction-builder).
//! - In tests, a mock impl returning canned responses verifies the
//!   sealer / driver logic in isolation.
//!
//! ## Why a trait
//!
//! The Sui Rust SDK is pre-1.0 and the API has historically shifted.
//! Keeping the surface narrow (two methods) means:
//!
//! - Tests don't pay Sui-RPC connection / authentication cost.
//! - An SDK bump that renames `Client::publish_transaction` or
//!   `Object::content` only requires updating
//!   [`crate::rpc`] — never the sealer or driver.
//! - Operators wanting a different RPC mechanism (e.g. direct JSON-RPC
//!   to a custom indexer) can implement the trait themselves.

use async_trait::async_trait;

use crate::error::Result;

/// Inputs to the on-chain `commit_batch` Move call, byte-for-byte
/// matching the Move function signature in
/// `/contracts/sui/receipt_anchor/sources/receipt_anchor.move`.
///
/// The sealer builds this from a [`yutha_receipt::SealedBatch`]; the
/// client impl encodes the fields as BCS PTB arguments and submits the
/// transaction.
#[derive(Debug, Clone)]
pub struct CommitBatchArgs {
    /// 32-byte SHA-256 Merkle root.
    pub batch_root: Vec<u8>,
    /// Number of receipts in the batch.
    pub count: u64,
    /// `min(monotonic_ns)` across the batch.
    pub ns_range_start: u64,
    /// `max(monotonic_ns)` across the batch.
    pub ns_range_end: u64,
    /// Per-action histogram, lex-sorted by key (the canonical
    /// preimage layout depends on this ordering — see
    /// `/spec/verifiability/sui-anchoring.md` §4.1). Sealer
    /// constructs from a `BTreeMap<String, u64>`, which iterates in
    /// the required order.
    pub histogram: Vec<(Vec<u8>, u64)>,
    /// 64-byte Ed25519 signature over the canonical preimage.
    pub sealer_signature: Vec<u8>,
}

/// Snapshot of the on-chain `SwarmAnchor` shared object's mutable state.
/// Read by the [`crate::driver::AnchorDriver`] at startup (to seed the
/// watermark) and after retryable Sui RPC failures (to re-align with
/// whatever batches landed in the meantime).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorState {
    /// Total batches committed against this `SwarmAnchor` so far.
    /// Serves as the public `batch_index` of the next batch.
    pub batch_count: u64,
    /// `ns_range_end` of the most recent successful batch. Drives the
    /// sealer's watermark.
    pub last_ns_range_end: u64,
}

/// Abstraction over the Sui RPC surface this crate uses. Two methods:
/// read the swarm anchor's mutable state, and submit a commit_batch
/// PTB. Everything else (object resolution, keypair handling,
/// transaction signing) is the impl's problem.
#[async_trait]
pub trait SuiAnchorClient: Send + Sync + std::fmt::Debug {
    /// Read the current `SwarmAnchor` state. Used at sealer-startup to
    /// initialize the watermark and after retryable failures to
    /// re-sync. The implementation MAY cache transient reads but MUST
    /// re-fetch when the caller explicitly asks (this trait's signature
    /// gives no caching hint; impls are free to optimize).
    async fn read_anchor_state(&self) -> Result<AnchorState>;

    /// Submit a `commit_batch` transaction. Returns the on-chain tx
    /// digest (32 bytes) once the transaction reaches Sui-finality.
    /// Implementations MUST distinguish transient RPC failures
    /// ([`crate::error::AnchorBackendError::RpcTransient`]) from
    /// on-chain aborts ([`crate::error::AnchorBackendError::OnChainAbort`])
    /// so the cadence loop can retry the former while alerting on the
    /// latter.
    async fn submit_commit_batch(&self, args: CommitBatchArgs) -> Result<Vec<u8>>;
}
