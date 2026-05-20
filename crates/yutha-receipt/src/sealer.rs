//! Sealer trait + `SealedBatch` + `LocalSealer` no-op default.
//!
//! Implements the trait surface specified in
//! [`/spec/verifiability/sui-anchoring.md`](../../../spec/verifiability/sui-anchoring.md)
//! §2. The Sealer is the seam between the receipt store and a
//! verifiability backend (currently Sui via `yutha-anchor-sui`; future
//! Walrus / other backends plug in by implementing the trait).
//!
//! ## Design constraints
//!
//! - **No Sui types here.** This crate compiles without any Sui SDK
//!   dependency. The Sui-specific impl lives in `yutha-anchor-sui`.
//!   `LocalSealer` (this crate) is the no-op fallback the control
//!   plane wires in when anchoring is disabled or set to `local`.
//! - **Async by design.** Sealing in production hits a remote
//!   blockchain RPC; the trait is `async_trait`-annotated to keep
//!   the call signature ergonomic for that case. `LocalSealer`'s
//!   impl is synchronous-in-body.
//! - **Non-blocking failures.** Sealer errors MUST NOT block receipt
//!   appends. The control plane runs the sealer in a background task;
//!   `SealError` carries enough detail to distinguish transient
//!   (retry) from permanent (alert) failures so the task can react.

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use thiserror::Error;
use yutha_core::{Hash, Timestamp};

use crate::merkle::{build_merkle, MerkleBatch};
use crate::receipt::Receipt;
use crate::ReceiptError;

/// Result of a successful seal operation.
///
/// Constructed by every [`Sealer`] impl. The fields are exactly what
/// the [`crate::store::ReceiptStore`] needs to populate per-receipt
/// `SealStatus` rows in storage (plus, for backend-anchored sealers,
/// the on-chain commitment id).
#[derive(Debug, Clone)]
pub struct SealedBatch {
    /// SHA-256 Merkle root over the batch's receipts.
    pub batch_root: Hash,
    /// Per-receipt inclusion proofs. `leaves[i].path` plus `leaves[i].leaf`
    /// reconstructs `batch_root` under the sorted-pair Merkle
    /// convention (see [`crate::merkle::verify_path`]).
    pub leaves: Vec<crate::merkle::LeafProof>,
    /// Wall-clock + monotonic timestamp the sealer recorded at
    /// commit time.
    pub sealed_at: Timestamp,
    /// Per-action-kind count over the batch. Keys are canonical
    /// action_kind strings ("envelope.send" etc.); values are the
    /// number of receipts in the batch with that action_kind. Sum
    /// of values equals `leaves.len()`.
    pub action_kind_histogram: BTreeMap<String, u64>,
    /// `[low, high]` of `occurred_at.monotonic_ns` across the batch.
    /// `[0, 0]` is only legal for a 1-receipt batch where the one
    /// receipt has `monotonic_ns == 0`.
    pub ns_range: (u64, u64),
    /// Backend-specific commitment id.
    ///
    /// For `SuiSealer`: the 32-byte Sui tx digest of the `commit_batch`
    /// transaction.
    ///
    /// For `LocalSealer`: an empty `Vec` — sealing happened locally
    /// without any external commitment.
    pub commitment_id: Vec<u8>,
}

/// Errors a [`Sealer`] can return.
///
/// Categorization is what the sealer-cadence task uses to decide
/// retry vs. operator-alert. See
/// [`/spec/verifiability/sui-anchoring.md`](../../../spec/verifiability/sui-anchoring.md)
/// §6.3 (cadence loop).
#[derive(Debug, Error)]
pub enum SealError {
    /// Empty batch handed to the sealer — caller bug.
    #[error("empty batch: at least one receipt required")]
    EmptyBatch,

    /// Merkle construction failed (e.g. duplicate receipt_ids in the
    /// batch). Bubbles up from [`crate::merkle::build_merkle`].
    #[error("merkle construction failed: {0}")]
    Merkle(String),

    /// Canonical preimage construction failed (e.g. histogram sum
    /// mismatch). Bubbles up from [`crate::preimage::canonical_preimage`].
    #[error("preimage construction failed: {0}")]
    Preimage(String),

    /// Backend RPC / connection failure. Retry on a sealer-cadence
    /// tick may succeed; the cadence loop SHOULD apply backoff
    /// before re-submitting.
    #[error("backend transient failure: {0}")]
    Transient(String),

    /// Backend semantic failure (e.g. on-chain ed25519_verify
    /// rejected, package id wrong). Retrying without operator
    /// intervention will not help; alert and wait.
    #[error("backend permanent failure: {0}")]
    Permanent(String),

    /// Sealer signing key error (file unreadable, malformed, etc.).
    #[error("signing failed: {0}")]
    Signing(String),
}

impl From<ReceiptError> for SealError {
    fn from(e: ReceiptError) -> Self {
        match e {
            ReceiptError::BatchInvalid(msg) => {
                // BatchInvalid covers both Merkle and preimage paths;
                // distinguish by content where useful, but a single
                // mapping is fine for v1.
                SealError::Merkle(msg)
            }
            other => SealError::Permanent(other.to_string()),
        }
    }
}

/// The seam between the receipt store and a verifiability backend.
///
/// Implementations:
/// - [`LocalSealer`] (this crate) — no-op; computes Merkle root +
///   paths locally, returns them with empty `commitment_id`.
///   Suitable for local development, tests, and the default control-
///   plane mode where anchoring is unset or set to `local`.
/// - `SuiSealer` (in `yutha-anchor-sui`, lands in H5) — submits a Sui
///   `commit_batch` transaction and returns the tx digest as
///   `commitment_id`.
///
/// The trait is intentionally narrow: one async method, one input
/// type, one output type. Cadence + watermark management live in the
/// control plane's sealer-driver task, not in the trait.
#[async_trait]
pub trait Sealer: Send + Sync + fmt::Debug {
    /// Seal a batch of receipts.
    ///
    /// Implementations MUST:
    ///   1. Compute the Merkle root over the receipts' canonical
    ///      bytes, ordered by `(occurred_at.monotonic_ns ASC,
    ///      receipt_id ASC)`.
    ///   2. Compute per-receipt Merkle paths under the sorted-pair
    ///      convention.
    ///   3. Commit to the verifiability backend (Sui transaction,
    ///      no-op log, etc.).
    ///   4. Return a `SealedBatch` describing the batch + commitment.
    ///
    /// Implementations SHOULD apply exponential backoff on transient
    /// backend failures (returning [`SealError::Transient`] only when
    /// the configured retry bound is exhausted).
    async fn seal_batch(&self, receipts: &[Receipt]) -> Result<SealedBatch, SealError>;
}

/// No-op default sealer.
///
/// Computes the Merkle root + paths + histogram locally and stamps the
/// resulting `SealedBatch` with `commitment_id = vec![]`. Useful for:
///
/// - Local development (no Sui localnet required).
/// - Unit / integration tests (deterministic, no external dependencies).
/// - Production deployments where anchoring is intentionally disabled
///   (the control plane wires this in when `--anchor-backend` is
///   `none` or `local`).
///
/// Receipts sealed by `LocalSealer` populate the `receipt_seal` table
/// with `on_chain_anchor_tx_digest = NULL`; consumers reading the seal
/// status correctly interpret this as "sealed locally only" per RFC 0014.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalSealer;

impl LocalSealer {
    /// Construct a fresh `LocalSealer`. The type is zero-sized; this
    /// is here for readability at call sites.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sealer for LocalSealer {
    async fn seal_batch(&self, receipts: &[Receipt]) -> Result<SealedBatch, SealError> {
        if receipts.is_empty() {
            return Err(SealError::EmptyBatch);
        }

        // Merkle root + paths.
        let MerkleBatch { root, leaves } = build_merkle(receipts).map_err(SealError::from)?;

        // Histogram + ns range derived from the same input set.
        let histogram = compute_histogram(receipts);
        let ns_range = compute_ns_range(receipts);

        Ok(SealedBatch {
            batch_root: root,
            leaves,
            sealed_at: Timestamp::now(),
            action_kind_histogram: histogram,
            ns_range,
            commitment_id: Vec::new(),
        })
    }
}

/// Build the per-action-kind count histogram for a batch.
///
/// Visible at module level so callers building [`SealedBatch`] outside
/// the trait can reuse the same canonical computation. The keys are
/// `Receipt::action_kind` strings; the values are the count of
/// receipts in the batch with that exact action_kind. Zero-count
/// keys are NOT inserted (the canonical preimage encoder rejects them).
pub fn compute_histogram(receipts: &[Receipt]) -> BTreeMap<String, u64> {
    let mut hist: BTreeMap<String, u64> = BTreeMap::new();
    for r in receipts {
        *hist.entry(r.action_kind.clone()).or_insert(0) += 1;
    }
    hist
}

/// Compute `(min, max)` of `occurred_at.monotonic_ns` across the batch.
///
/// Panics on empty input — callers MUST check non-empty first.
/// `LocalSealer` does so via [`SealError::EmptyBatch`].
pub fn compute_ns_range(receipts: &[Receipt]) -> (u64, u64) {
    let mut iter = receipts.iter().map(|r| r.occurred_at.monotonic_ns);
    let first = iter
        .next()
        .expect("compute_ns_range requires non-empty input");
    iter.fold((first, first), |(lo, hi), v| (lo.min(v), hi.max(v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use crate::receipt::Receipt;
    use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};

    fn fixed_swarm() -> SwarmId {
        SwarmId::from_bytes(&[1u8; 16]).expect("16 bytes")
    }

    fn fixed_agent(seed: u8) -> AgentId {
        let mut bytes = [0u8; 16];
        bytes[0] = seed;
        AgentId::from_bytes(&bytes).expect("16 bytes")
    }

    fn fixture(monotonic_ns: u64, seed: u8, action_kind: &str) -> Receipt {
        Receipt::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(fixed_swarm())
            .actor(fixed_agent(seed))
            .action_kind(action_kind)
            .causal(CausalRef::default())
            .evidence(Evidence::new("k", "test/type", vec![seed]))
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::new("2026-05-19T00:00:00Z".into(), monotonic_ns).unwrap())
            .build()
            .expect("fixture")
    }

    #[tokio::test]
    async fn local_sealer_returns_consistent_batch() {
        let sealer = LocalSealer::new();
        let receipts = vec![
            fixture(100, 1, "envelope.send"),
            fixture(200, 2, "envelope.deliver"),
            fixture(300, 3, "envelope.send"),
        ];
        let batch = sealer.seal_batch(&receipts).await.unwrap();

        // Three receipts → three leaf-proofs.
        assert_eq!(batch.leaves.len(), 3);

        // Histogram aggregates per action_kind.
        assert_eq!(batch.action_kind_histogram.len(), 2);
        assert_eq!(batch.action_kind_histogram["envelope.send"], 2);
        assert_eq!(batch.action_kind_histogram["envelope.deliver"], 1);

        // ns_range covers (100, 300).
        assert_eq!(batch.ns_range, (100, 300));

        // commitment_id is empty for LocalSealer.
        assert!(batch.commitment_id.is_empty());

        // Every leaf proof reconstructs the root.
        for proof in &batch.leaves {
            assert!(crate::merkle::verify_path(
                &proof.leaf,
                &proof.path,
                &batch.batch_root
            ));
        }
    }

    #[tokio::test]
    async fn local_sealer_rejects_empty_batch() {
        let sealer = LocalSealer::new();
        let err = sealer.seal_batch(&[]).await.unwrap_err();
        assert!(matches!(err, SealError::EmptyBatch));
    }

    #[tokio::test]
    async fn local_sealer_rejects_duplicate_receipts() {
        let sealer = LocalSealer::new();
        let r = fixture(100, 1, "envelope.send");
        let err = sealer.seal_batch(&[r.clone(), r]).await.unwrap_err();
        // Duplicate detection lives in merkle::build_merkle → returns
        // BatchInvalid → mapped to SealError::Merkle by `impl From`.
        assert!(
            matches!(err, SealError::Merkle(msg) if msg.contains("duplicate")),
            "expected SealError::Merkle(duplicate)"
        );
    }

    #[tokio::test]
    async fn local_sealer_handles_single_receipt() {
        let sealer = LocalSealer::new();
        let r = fixture(42, 1, "agent.register");
        let batch = sealer.seal_batch(&[r]).await.unwrap();
        assert_eq!(batch.leaves.len(), 1);
        assert_eq!(batch.leaves[0].path.len(), 0);
        assert_eq!(batch.batch_root, batch.leaves[0].leaf);
        assert_eq!(batch.ns_range, (42, 42));
        assert_eq!(batch.action_kind_histogram["agent.register"], 1);
    }

    #[test]
    fn histogram_aggregates_correctly() {
        let receipts = vec![
            fixture(100, 1, "envelope.send"),
            fixture(200, 2, "envelope.send"),
            fixture(300, 3, "envelope.send"),
            fixture(400, 4, "envelope.deliver"),
        ];
        let hist = compute_histogram(&receipts);
        assert_eq!(hist.len(), 2);
        assert_eq!(hist["envelope.send"], 3);
        assert_eq!(hist["envelope.deliver"], 1);
    }

    #[test]
    fn ns_range_includes_endpoints() {
        let receipts = vec![
            fixture(500, 1, "x"),
            fixture(100, 2, "x"),
            fixture(900, 3, "x"),
            fixture(300, 4, "x"),
        ];
        assert_eq!(compute_ns_range(&receipts), (100, 900));
    }

    #[test]
    fn ns_range_single_value() {
        let receipts = vec![fixture(42, 1, "x")];
        assert_eq!(compute_ns_range(&receipts), (42, 42));
    }
}
