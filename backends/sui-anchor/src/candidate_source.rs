//! `ReceiptStoreCandidateSource` — the production
//! [`crate::driver::CandidateSource`] impl, used by the control plane
//! when spawning an [`crate::driver::AnchorDriver`].
//!
//! Wraps an `Arc<dyn ReceiptStore>` and translates the driver's
//! `(watermark, max_batch_size)` request into a
//! [`yutha_receipt::Query::ByTimeRange`] query. The store's existing
//! pagination + ordering guarantees do all the heavy lifting; this
//! shim is intentionally thin so a future store-side optimisation
//! (a dedicated `unsealed_after` query path) drops in transparently.
//!
//! ## Watermark semantics
//!
//! The driver's `watermark` is the `last_ns_range_end` from the most
//! recent successful seal — i.e. the `monotonic_ns` of the last
//! receipt already sealed. So the candidate window is **strictly
//! greater than** the watermark; we encode that as
//! `from.monotonic_ns = watermark.saturating_add(1)` and
//! `to.monotonic_ns = u64::MAX`.
//!
//! ## Wall-clock sentinel
//!
//! [`TimeRangeQuery`] takes `Timestamp` values (wall_clock + monotonic
//! tuple) because the type is shared with cross-process bound checks
//! that need wall-clock. The Postgres / Memory backends both filter
//! on `monotonic_ns` only (the spec's authoritative ordering field),
//! so the wall_clock string here is a sentinel that just needs to
//! parse as RFC 3339. We use the Unix epoch for `from` and a far-future
//! date for `to`; both backends ignore them.
//!
//! ## Filtering on seal status
//!
//! We don't filter by `SealStatus` in the query because the driver's
//! watermark already encodes "haven't sealed past this ns yet." Any
//! receipt with `occurred_at_ns > watermark` is by construction
//! unsealed. The seal-state lookup is on a different code path
//! (`SealStore::seal_status`) and is for off-chain observability.

use std::sync::Arc;

use async_trait::async_trait;
use yutha_core::Timestamp;
use yutha_receipt::{Query, Receipt, ReceiptError, ReceiptStore, TimeRangeQuery};

use crate::driver::{CandidateSource, DriverError};

/// [`CandidateSource`] impl backed by any [`ReceiptStore`].
///
/// Construct once at startup with the same `Arc<dyn ReceiptStore>` the
/// rest of the control plane reads from; the driver's polling reads
/// see the same receipts the appenders are writing without any extra
/// plumbing.
#[derive(Clone)]
pub struct ReceiptStoreCandidateSource {
    store: Arc<dyn ReceiptStore>,
}

impl std::fmt::Debug for ReceiptStoreCandidateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptStoreCandidateSource").finish()
    }
}

impl ReceiptStoreCandidateSource {
    /// Wrap a receipt store as a candidate source.
    pub fn new(store: Arc<dyn ReceiptStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl CandidateSource for ReceiptStoreCandidateSource {
    async fn fetch_candidates(
        &self,
        watermark: u64,
        max_batch_size: usize,
    ) -> Result<Vec<Receipt>, DriverError> {
        // (watermark, u64::MAX] — strictly greater than the last sealed ns.
        // saturating_add covers the edge case where the watermark is
        // already at u64::MAX (means everything is sealed; nothing to do).
        let from_ns = watermark.saturating_add(1);
        if from_ns == u64::MAX {
            // Watermark saturated; no candidates possible.
            return Ok(Vec::new());
        }

        // Build the time-range query. Wall-clock strings are RFC 3339
        // sentinels — the backends ignore them in this query path
        // (filter is on monotonic_ns only).
        let from = Timestamp::new("1970-01-01T00:00:00Z".to_string(), from_ns)
            .map_err(|e| DriverError::CandidateSource(format!("construct from-timestamp: {e}")))?;
        let to = Timestamp::new("9999-12-31T23:59:59Z".to_string(), u64::MAX)
            .map_err(|e| DriverError::CandidateSource(format!("construct to-timestamp: {e}")))?;
        let query = Query::ByTimeRange(TimeRangeQuery { from, to });

        let page = self
            .store
            .query(query, None)
            .await
            .map_err(|e| DriverError::CandidateSource(map_receipt_error(e)))?;

        // SORT BEFORE TRUNCATE — load-bearing for correctness.
        //
        // The driver advances its watermark to `ns_range_end` (= max
        // monotonic_ns of the sealed batch) after each successful
        // commit. If we truncate an unsorted result, the next watermark
        // is the max of the *truncated* set, and any receipts with
        // ns in (truncated_max, original_max] become unreachable —
        // they'd be skipped on the next poll because the watermark
        // has already advanced past them.
        //
        // The Postgres backend sorts in the query (`ORDER BY
        // occurred_at_ns`), but `MemoryStore::query` returns HashMap
        // iteration order. Sort here so the candidate source
        // contract is "ascending by monotonic_ns" regardless of
        // backend ordering guarantees.
        let mut receipts = page.receipts;
        receipts.sort_by_key(|r| r.occurred_at.monotonic_ns);
        if receipts.len() > max_batch_size {
            receipts.truncate(max_batch_size);
        }
        Ok(receipts)
    }
}

/// Map a [`ReceiptError`] to a short string for the driver's
/// `CandidateSource` arm. The driver logs + retries on transient
/// errors; the specific variant isn't load-bearing past the log line.
fn map_receipt_error(e: ReceiptError) -> String {
    match e {
        ReceiptError::Backend(msg) => format!("receipt store backend: {msg}"),
        ReceiptError::InvalidQuery(msg) => format!("invalid query: {msg}"),
        other => format!("receipt store: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_core::{AgentId, CausalRef, PublicKey, SpecVersion, SwarmId};
    use yutha_crypto::sign::generate_keypair;
    use yutha_receipt::{
        AppendOptions, Evidence, MemoryStore, ReceiptBuilder, SignatureRole, SignedBy,
        StaticPassportResolver,
    };

    /// Test fixture: build a receipt at a specific monotonic_ns,
    /// signed by a fresh actor key. Returns the receipt + its actor +
    /// the signing key's public counterpart so the test can build a
    /// matching resolver.
    fn signed_at_monotonic(
        monotonic_ns: u64,
        seed: u8,
    ) -> (yutha_receipt::Receipt, AgentId, PublicKey) {
        let key = generate_keypair();
        let actor = {
            let mut b = [0u8; 16];
            b[0] = seed;
            AgentId::from_bytes(&b).unwrap()
        };
        let mut r = ReceiptBuilder::new()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::from_bytes(&[0x42; 16]).unwrap())
            .actor(actor)
            .action_kind("envelope.send")
            .causal(CausalRef::default())
            .evidence(Evidence::new("k", "type.yutha.dev/v1/Bytes", vec![seed]))
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::new("2026-05-20T00:00:00Z".into(), monotonic_ns).unwrap())
            .build()
            .unwrap();
        let bytes = yutha_crypto::canonical::Canonical::canonical_bytes(&r).unwrap();
        let sig = key.sign_message(&bytes);
        r.signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
        (r, actor, key.public())
    }

    /// Append `receipts` to `store`, using a resolver that knows every
    /// actor key used by the fixtures.
    async fn seed(
        store: &MemoryStore,
        fixtures: Vec<(yutha_receipt::Receipt, AgentId, PublicKey)>,
    ) {
        let mut resolver = StaticPassportResolver::new();
        for (_, actor, pk) in &fixtures {
            resolver = resolver.with_actor(*actor, pk.clone());
        }
        for (r, _, _) in fixtures {
            store
                .append(r, AppendOptions::default(), &resolver)
                .await
                .expect("append should succeed in tests");
        }
    }

    #[tokio::test]
    async fn fetch_candidates_returns_receipts_past_watermark() {
        let store = Arc::new(MemoryStore::new());
        let r1 = signed_at_monotonic(100, 1);
        let r2 = signed_at_monotonic(200, 2);
        let r3 = signed_at_monotonic(300, 3);
        seed(&store, vec![r1, r2, r3]).await;

        let src = ReceiptStoreCandidateSource::new(store.clone() as Arc<dyn ReceiptStore>);
        // Watermark 150 → expect monotonic_ns 200 + 300 (strictly greater).
        let candidates = src.fetch_candidates(150, 10).await.unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].occurred_at.monotonic_ns, 200);
        assert_eq!(candidates[1].occurred_at.monotonic_ns, 300);
    }

    #[tokio::test]
    async fn fetch_candidates_truncates_to_max_batch_size() {
        let store = Arc::new(MemoryStore::new());
        let fixtures: Vec<_> = (0..5)
            .map(|i| signed_at_monotonic(100 + i, i as u8 + 1))
            .collect();
        seed(&store, fixtures).await;

        let src = ReceiptStoreCandidateSource::new(store.clone() as Arc<dyn ReceiptStore>);
        let candidates = src.fetch_candidates(0, 3).await.unwrap();
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].occurred_at.monotonic_ns, 100);
        assert_eq!(candidates[1].occurred_at.monotonic_ns, 101);
        assert_eq!(candidates[2].occurred_at.monotonic_ns, 102);
    }

    #[tokio::test]
    async fn fetch_candidates_empty_past_watermark_is_ok() {
        let store = Arc::new(MemoryStore::new());
        let r1 = signed_at_monotonic(100, 1);
        seed(&store, vec![r1]).await;

        let src = ReceiptStoreCandidateSource::new(store.clone() as Arc<dyn ReceiptStore>);
        let candidates = src.fetch_candidates(200, 10).await.unwrap();
        assert!(candidates.is_empty());
    }

    #[tokio::test]
    async fn fetch_candidates_at_saturated_watermark_returns_empty() {
        let store = Arc::new(MemoryStore::new());
        let r1 = signed_at_monotonic(100, 1);
        seed(&store, vec![r1]).await;

        let src = ReceiptStoreCandidateSource::new(store.clone() as Arc<dyn ReceiptStore>);
        // Watermark = u64::MAX - 1 → saturating_add(1) = u64::MAX,
        // the explicit early-return branch fires. Empty result.
        let candidates = src.fetch_candidates(u64::MAX - 1, 10).await.unwrap();
        assert!(candidates.is_empty());
    }
}
