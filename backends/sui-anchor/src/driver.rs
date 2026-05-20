//! `AnchorDriver` — the hybrid-cadence sealer driver.
//!
//! Public so the control plane can construct one + spawn it via
//! `tokio::spawn(driver.run())`. The driver:
//!
//! 1. On startup, reads the on-chain `SwarmAnchor` via the sealer's
//!    [`crate::client::SuiAnchorClient`] to discover the current
//!    watermark (`last_ns_range_end`).
//! 2. Polls the [`yutha_receipt::ReceiptStore`] for unsealed receipts
//!    (`occurred_at_ns > watermark`).
//! 3. Triggers a seal when EITHER (a) the count threshold is reached
//!    or (b) the time threshold has elapsed since the last seal.
//! 4. Calls the [`yutha_receipt::Sealer`] (typically
//!    [`crate::sealer::SuiSealer`]) to produce a [`SealedBatch`].
//! 5. Records the batch via the [`yutha_receipt::SealStore`].
//! 6. Advances the watermark; sleeps until the next cadence tick.
//!
//! The receipt-stream layer for the cadence-loop poll is intentionally
//! abstract — we accept any `dyn FnMut` that returns the candidate
//! batch. In production the control plane wires this to a real
//! Postgres query; in tests we hand it a vector.
//!
//! Retry policy on transient client failures: exponential backoff up
//! to `retry_attempts`; then surface to the operator and continue the
//! loop (the failed batch will retry on the next tick once the
//! watermark hasn't advanced).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;
use yutha_receipt::{Receipt, SealError, SealStore, Sealer};

/// Configuration knobs for the hybrid cadence loop. Mirrors the CLI
/// flag surface in `/spec/verifiability/sui-anchoring.md` §6.1.
#[derive(Debug, Clone)]
pub struct AnchorDriverConfig {
    /// Trigger a seal when this many unsealed receipts have accumulated.
    /// Default 100.
    pub batch_count_threshold: usize,
    /// Trigger a seal at most this often, regardless of count.
    /// Default 10s.
    pub batch_time_threshold: Duration,
    /// Hard ceiling on a single batch's size. Protects against
    /// backlog blowouts after RPC downtime. Default 1000.
    pub max_batch_size: usize,
    /// Max retries per batch on transient backend failure before
    /// giving up and waiting for the next tick. Default 5.
    pub retry_attempts: u32,
    /// Initial backoff after a transient failure. Doubled each
    /// retry up to a cap. Default 200ms.
    pub initial_backoff: Duration,
    /// Cap on the exponential backoff. Default 5s.
    pub max_backoff: Duration,
    /// Sleep duration between polls when there's nothing to seal.
    /// Should be ≤ `batch_time_threshold` so the time-trigger fires
    /// promptly. Default 1s.
    pub idle_poll_interval: Duration,
}

impl Default for AnchorDriverConfig {
    fn default() -> Self {
        Self {
            batch_count_threshold: 100,
            batch_time_threshold: Duration::from_secs(10),
            max_batch_size: 1000,
            retry_attempts: 5,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
            idle_poll_interval: Duration::from_secs(1),
        }
    }
}

/// Returns the next batch of candidate receipts (or empty if none),
/// given the current watermark + cap. Implementations:
///
/// - **Production** (in `yutha-control-plane`): SQL query against the
///   Postgres receipt store, filtering for `occurred_at_ns > watermark`,
///   ordered + limited.
/// - **Tests**: a `Mutex<Vec<Receipt>>` returning batches by index.
///
/// The driver doesn't care about the source — only that the function
/// returns receipts that haven't been sealed yet, in some sensible
/// order (sort happens inside [`yutha_receipt::build_merkle`] so this
/// fn can return arbitrary order, but limiting to a stable order
/// helps log diagnostics).
#[async_trait::async_trait]
pub trait CandidateSource: Send + Sync + std::fmt::Debug {
    /// Fetch at most `max_batch_size` receipts with
    /// `occurred_at_ns > watermark`. Empty result = nothing to seal.
    async fn fetch_candidates(
        &self,
        watermark: u64,
        max_batch_size: usize,
    ) -> Result<Vec<Receipt>, DriverError>;
}

/// Errors specific to the cadence loop. Most failures surface as
/// `tracing::error!` calls + a continued loop; only construction-time
/// problems propagate via `Result`.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// Candidate source backend failed (Postgres down, etc.).
    /// Driver logs + waits for the next tick.
    #[error("candidate source error: {0}")]
    CandidateSource(String),
    /// Anchor-backend error mapped from a transient/permanent
    /// distinction at the [`Sealer`] boundary.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// Wrapper for [`yutha_receipt::ReceiptError`] coming from the
    /// [`SealStore::record_sealed_batch`] step.
    #[error("record sealed batch: {0}")]
    RecordSealedBatch(String),
}

/// Background-task driver. Constructed at startup; the control plane
/// calls `tokio::spawn(driver.run())` and the loop runs until the
/// process exits (or a future [`AnchorDriver::shutdown`] is added).
pub struct AnchorDriver {
    config: AnchorDriverConfig,
    sealer: Arc<dyn Sealer>,
    candidate_source: Arc<dyn CandidateSource>,
    seal_store: Arc<dyn SealStore>,
    /// In-memory watermark. Advances after each successful seal.
    /// Initialized from the on-chain `SwarmAnchor.last_ns_range_end`
    /// (via [`AnchorDriver::new`]).
    watermark: u64,
    /// Wakeable notify; reserved for future "force seal now" wiring.
    /// Currently unused — the loop wakes on its own cadence.
    #[allow(dead_code)]
    notify: Arc<Notify>,
}

impl AnchorDriver {
    /// Construct a driver. `initial_watermark` should come from
    /// `SuiSealer::read_anchor_state().await?.last_ns_range_end` —
    /// the control plane reads it at startup, hands it here.
    pub fn new(
        config: AnchorDriverConfig,
        sealer: Arc<dyn Sealer>,
        candidate_source: Arc<dyn CandidateSource>,
        seal_store: Arc<dyn SealStore>,
        initial_watermark: u64,
    ) -> Self {
        Self {
            config,
            sealer,
            candidate_source,
            seal_store,
            watermark: initial_watermark,
            notify: Arc::new(Notify::new()),
        }
    }

    /// Main loop. Doesn't return until the process exits or a future
    /// shutdown signal is wired in. Logs each batch via `tracing::info!`.
    pub async fn run(mut self) {
        let mut last_seal_at = Instant::now();
        tracing::info!(
            watermark = self.watermark,
            count_threshold = self.config.batch_count_threshold,
            time_threshold = ?self.config.batch_time_threshold,
            "AnchorDriver starting"
        );

        loop {
            // Pull candidates.
            let candidates = match self
                .candidate_source
                .fetch_candidates(self.watermark, self.config.max_batch_size)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(?e, "candidate fetch failed; backing off");
                    tokio::time::sleep(self.config.idle_poll_interval).await;
                    continue;
                }
            };

            let elapsed = last_seal_at.elapsed();
            let count = candidates.len();
            let should_seal = !candidates.is_empty()
                && (count >= self.config.batch_count_threshold
                    || elapsed >= self.config.batch_time_threshold);

            if !should_seal {
                tokio::time::sleep(self.config.idle_poll_interval).await;
                continue;
            }

            // Try to seal, with exponential backoff on transient errors.
            match self.try_seal_with_backoff(&candidates).await {
                Ok(new_watermark) => {
                    self.watermark = new_watermark;
                    last_seal_at = Instant::now();
                    tracing::info!(count, watermark = self.watermark, "sealed batch");
                }
                Err(DriverError::Seal(SealError::Transient(msg))) => {
                    tracing::warn!(
                        msg,
                        count,
                        "transient seal failure exhausted; retry on next tick"
                    );
                    tokio::time::sleep(self.config.idle_poll_interval).await;
                }
                Err(other) => {
                    tracing::error!(
                        ?other,
                        count,
                        "permanent seal failure — operator must intervene"
                    );
                    // Long backoff on permanent failures.
                    tokio::time::sleep(self.config.max_backoff).await;
                }
            }
        }
    }

    async fn try_seal_with_backoff(&self, receipts: &[Receipt]) -> Result<u64, DriverError> {
        let mut backoff = self.config.initial_backoff;
        let mut attempt: u32 = 0;
        loop {
            match self.sealer.seal_batch(receipts).await {
                Ok(batch) => {
                    // Capture the ns_range_end before moving the batch.
                    let new_watermark = batch.ns_range.1;
                    // Record in the seal store.
                    self.seal_store
                        .record_sealed_batch(&batch)
                        .await
                        .map_err(|e| DriverError::RecordSealedBatch(e.to_string()))?;
                    return Ok(new_watermark);
                }
                Err(SealError::Transient(msg)) if attempt < self.config.retry_attempts => {
                    tracing::warn!(
                        attempt,
                        msg,
                        ?backoff,
                        "transient seal failure; backing off"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(self.config.max_backoff);
                    attempt += 1;
                }
                Err(other) => return Err(DriverError::Seal(other)),
            }
        }
    }
}

impl std::fmt::Debug for AnchorDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorDriver")
            .field("config", &self.config)
            .field("watermark", &self.watermark)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
    use yutha_receipt::{
        compute_histogram, compute_ns_range, Evidence, MemoryStore, ReceiptBuilder, SealedBatch,
    };

    #[derive(Debug)]
    struct VecCandidateSource {
        inner: Mutex<Vec<Receipt>>,
    }

    impl VecCandidateSource {
        fn new(receipts: Vec<Receipt>) -> Self {
            Self {
                inner: Mutex::new(receipts),
            }
        }
    }

    #[async_trait]
    impl CandidateSource for VecCandidateSource {
        async fn fetch_candidates(
            &self,
            watermark: u64,
            max_batch_size: usize,
        ) -> Result<Vec<Receipt>, DriverError> {
            let guard = self.inner.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|r| r.occurred_at.monotonic_ns > watermark)
                .take(max_batch_size)
                .cloned()
                .collect())
        }
    }

    /// Stub Sealer that produces a SealedBatch without going through
    /// the real Sui flow. Lets us test the driver in isolation.
    #[derive(Debug)]
    struct StubSealer {
        call_count: Mutex<usize>,
    }

    #[async_trait]
    impl Sealer for StubSealer {
        async fn seal_batch(&self, receipts: &[Receipt]) -> Result<SealedBatch, SealError> {
            *self.call_count.lock().unwrap() += 1;
            // Use the same canonical computations LocalSealer uses, so
            // the resulting batch round-trips correctly through
            // record_sealed_batch.
            let merkle = yutha_receipt::build_merkle(receipts)
                .map_err(|e| SealError::Merkle(e.to_string()))?;
            let histogram = compute_histogram(receipts);
            let ns_range = compute_ns_range(receipts);
            Ok(SealedBatch {
                batch_root: merkle.root,
                leaves: merkle.leaves,
                sealed_at: Timestamp::now(),
                action_kind_histogram: histogram,
                ns_range,
                commitment_id: vec![0xFF; 32],
            })
        }
    }

    fn fixture(monotonic_ns: u64, seed: u8) -> Receipt {
        ReceiptBuilder::new()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::from_bytes(&[0x42; 16]).unwrap())
            .actor({
                let mut b = [0u8; 16];
                b[0] = seed;
                AgentId::from_bytes(&b).unwrap()
            })
            .action_kind("envelope.send")
            .causal(CausalRef::default())
            .evidence(Evidence::new("k", "test/type", vec![seed]))
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::new("2026-05-19T00:00:00Z".into(), monotonic_ns).unwrap())
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn driver_seals_when_count_threshold_hits() {
        let receipts: Vec<Receipt> = (0..5).map(|i| fixture(100 + i as u64, i as u8)).collect();
        let source = Arc::new(VecCandidateSource::new(receipts));
        let sealer = Arc::new(StubSealer {
            call_count: Mutex::new(0),
        });
        let store: Arc<dyn SealStore> = Arc::new(MemoryStore::new());

        let config = AnchorDriverConfig {
            batch_count_threshold: 3, // small threshold; will fire immediately
            batch_time_threshold: Duration::from_secs(60), // not reachable in this test
            idle_poll_interval: Duration::from_millis(50),
            ..Default::default()
        };
        let driver = AnchorDriver::new(config, sealer.clone(), source, store, 0);

        // Spawn the driver and let it run briefly.
        let handle = tokio::spawn(driver.run());
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.abort();

        // The sealer should have been called at least once. The exact
        // number depends on timing — assert ≥ 1 (the batch fires once
        // for the 5-receipt set; watermark then advances, no more
        // candidates).
        let calls = *sealer.call_count.lock().unwrap();
        assert!(calls >= 1, "sealer should have been called");
    }
}
