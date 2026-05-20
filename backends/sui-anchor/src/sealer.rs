//! [`SuiSealer`] — the [`yutha_receipt::Sealer`] impl that anchors on Sui.
//!
//! Composes a [`crate::client::SuiAnchorClient`] (production: Sui RPC;
//! test: mock) with the [`yutha_receipt::LocalSealer`]'s Merkle
//! + histogram computation. Adds the on-chain commit step:
//!
//! 1. Compute Merkle root + paths + histogram + ns-range via the same
//!    deterministic functions [`yutha_receipt::LocalSealer`] uses
//!    (reused directly to keep canonical-bytes lockstep).
//! 2. Build the canonical preimage per
//!    `/spec/verifiability/sui-anchoring.md` §4.
//! 3. Ed25519-sign the preimage with the sealer key the client owns
//!    (the client also knows the on-chain registered public key, so
//!    a mismatch surfaces as `ESealerKeyMismatch` on commit).
//! 4. Hand the [`crate::client::CommitBatchArgs`] to the client; await
//!    on-chain confirmation; receive the tx digest back.
//! 5. Return a [`yutha_receipt::SealedBatch`] with `commitment_id` set
//!    to the 32-byte Sui tx digest.

use std::sync::Arc;

use async_trait::async_trait;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_crypto::Signer;
use sui_sdk_types::Ed25519Signature;
use yutha_core::{Hash, SwarmId, Timestamp};
use yutha_receipt::{
    build_merkle, canonical_preimage, compute_histogram, compute_ns_range, MerkleBatch, Receipt,
    SealError, SealedBatch, Sealer,
};

use crate::client::{CommitBatchArgs, SuiAnchorClient};
use crate::error::AnchorBackendError;

/// Anchors batches on Sui.
///
/// Construct once at startup with the [`crate::client::SuiAnchorClient`]
/// already connected; the sealer is cloneable and the trait is
/// `async_trait`, so multiple concurrent batches can call
/// [`SuiSealer::seal_batch`] without an extra synchronization layer
/// (the client impl is responsible for any internal mutex).
#[derive(Debug, Clone)]
pub struct SuiSealer {
    inner: Arc<SuiSealerInner>,
}

#[derive(Debug)]
struct SuiSealerInner {
    client: Box<dyn SuiAnchorClient>,
    sealer_signing: SealerSigning,
    swarm_id: SwarmId,
}

/// How the sealer signs the canonical preimage that gets embedded in
/// the on-chain `commit_batch` call.
///
/// Two variants exist so tests can drive [`SuiSealer::seal_batch`]
/// without dragging a real Ed25519 keypair through every fixture.
/// Production code constructs `Live`; tests construct `PreBaked`.
#[derive(Debug, Clone)]
pub enum SealerSigning {
    /// Production: sign the preimage with the Ed25519 key whose
    /// public counterpart the operator registered on-chain as
    /// `SwarmAnchor.sealer_pubkey`. Mismatch surfaces as
    /// `ESealerKeyMismatch` on commit.
    Live(Arc<Ed25519PrivateKey>),
    /// Tests: a pre-baked signature is returned regardless of input.
    /// Useful for hooking the trait abstraction up to a mock client
    /// without exercising real crypto.
    #[cfg(test)]
    PreBaked(Vec<u8>),
}

impl SealerSigning {
    fn sign(&self, preimage: &[u8]) -> Result<Vec<u8>, AnchorBackendError> {
        match self {
            Self::Live(key) => {
                // sui-crypto's `Signer<Ed25519Signature>` impl signs raw
                // bytes. The Move-side `ed25519_verify(sig, pubkey, msg)`
                // re-runs verification on the same bytes after
                // reconstructing the canonical preimage on-chain; a
                // mismatch surfaces as `ESealerKeyMismatch`.
                let sig: Ed25519Signature = key.try_sign(preimage).map_err(|e| {
                    AnchorBackendError::SealerKey(format!("ed25519 sign preimage: {e}"))
                })?;
                Ok(sig.inner().to_vec())
            }
            #[cfg(test)]
            Self::PreBaked(s) => Ok(s.clone()),
        }
    }
}

impl SuiSealer {
    /// Construct a SuiSealer.
    ///
    /// `swarm_id` is the 16-byte UUID identifying the Yutha swarm —
    /// matches the value stored in the on-chain `SwarmAnchor` and is
    /// used as the first 16 bytes of the canonical preimage.
    pub fn new(
        client: Box<dyn SuiAnchorClient>,
        sealer_key: Ed25519PrivateKey,
        swarm_id: SwarmId,
    ) -> Self {
        Self {
            inner: Arc::new(SuiSealerInner {
                client,
                sealer_signing: SealerSigning::Live(Arc::new(sealer_key)),
                swarm_id,
            }),
        }
    }

    /// Test constructor. Skips the Ed25519 key path; signatures are
    /// the pre-baked bytes you supply. Use to drive
    /// [`SuiSealer::seal_batch`] in unit tests against a mock client.
    #[cfg(test)]
    pub(crate) fn new_for_tests(
        client: Box<dyn SuiAnchorClient>,
        prebaked_signature: Vec<u8>,
        swarm_id: SwarmId,
    ) -> Self {
        Self {
            inner: Arc::new(SuiSealerInner {
                client,
                sealer_signing: SealerSigning::PreBaked(prebaked_signature),
                swarm_id,
            }),
        }
    }

    /// Read the on-chain SwarmAnchor state. Used by
    /// [`crate::driver::AnchorDriver`] to seed the watermark at
    /// startup; surfaced publicly so the control plane can do its own
    /// health check / observability against the same trait.
    pub async fn read_anchor_state(
        &self,
    ) -> Result<crate::client::AnchorState, AnchorBackendError> {
        self.inner.client.read_anchor_state().await
    }
}

#[async_trait]
impl Sealer for SuiSealer {
    async fn seal_batch(&self, receipts: &[Receipt]) -> Result<SealedBatch, SealError> {
        if receipts.is_empty() {
            return Err(SealError::EmptyBatch);
        }

        // Step 1: Merkle + histogram + ns-range — same deterministic
        // computation LocalSealer uses, reused here so the canonical
        // bytes match across the two sealers byte-for-byte.
        let MerkleBatch { root, leaves } = build_merkle(receipts).map_err(SealError::from)?;
        let histogram = compute_histogram(receipts);
        let (ns_start, ns_end) = compute_ns_range(receipts);

        // Step 2: canonical preimage. yutha-receipt's encoder validates
        // structure (sum == count, key lengths, sort-order via BTreeMap)
        // and surfaces preimage errors as ReceiptError::BatchInvalid →
        // SealError::Preimage via the From impl.
        let preimage = canonical_preimage(
            &self.inner.swarm_id,
            &root,
            receipts.len() as u64,
            ns_start,
            ns_end,
            &histogram,
        )
        .map_err(|e| match e {
            yutha_receipt::ReceiptError::BatchInvalid(msg) => SealError::Preimage(msg),
            other => SealError::Permanent(other.to_string()),
        })?;

        // Step 3: sign the preimage.
        let signature = self
            .inner
            .sealer_signing
            .sign(&preimage)
            .map_err(SealError::from)?;

        // Step 4: build the Move-call args, hand to the client.
        // Histogram BTreeMap → sorted Vec<(Vec<u8>, u64)> — preserves
        // the lex-ascending order the on-chain verify expects.
        let histogram_args: Vec<(Vec<u8>, u64)> = histogram
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), *v))
            .collect();

        let args = CommitBatchArgs {
            batch_root: root.digest.clone(),
            count: receipts.len() as u64,
            ns_range_start: ns_start,
            ns_range_end: ns_end,
            histogram: histogram_args,
            sealer_signature: signature,
        };

        let tx_digest = self
            .inner
            .client
            .submit_commit_batch(args)
            .await
            .map_err(SealError::from)?;

        // Step 5: package up SealedBatch.
        Ok(SealedBatch {
            batch_root: root,
            leaves,
            sealed_at: Timestamp::now(),
            action_kind_histogram: histogram,
            ns_range: (ns_start, ns_end),
            commitment_id: tx_digest,
        })
    }
}

// Suppress an unused-import warning on Hash when feature combinations
// don't need it. Hash is referenced through the `leaves` iter type
// but Rust's import tracker is conservative here.
#[allow(dead_code)]
fn _hash_used(_: Hash) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::AnchorState;
    use std::sync::Mutex;
    use yutha_core::{AgentId, CausalRef, SpecVersion};
    use yutha_receipt::{Evidence, ReceiptBuilder};

    #[derive(Debug, Default)]
    struct MockClient {
        anchor_state: Mutex<AnchorState>,
        submitted: Mutex<Vec<CommitBatchArgs>>,
        return_digest: Vec<u8>,
        fail_with: Mutex<Option<AnchorBackendError>>,
    }

    impl MockClient {
        fn new() -> Self {
            Self {
                anchor_state: Mutex::new(AnchorState {
                    batch_count: 0,
                    last_ns_range_end: 0,
                }),
                submitted: Mutex::new(vec![]),
                return_digest: vec![0xAB; 32],
                fail_with: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl SuiAnchorClient for MockClient {
        async fn read_anchor_state(&self) -> crate::error::Result<AnchorState> {
            Ok(self.anchor_state.lock().unwrap().clone())
        }
        async fn submit_commit_batch(
            &self,
            args: CommitBatchArgs,
        ) -> crate::error::Result<Vec<u8>> {
            if let Some(err) = self.fail_with.lock().unwrap().take() {
                return Err(err);
            }
            self.submitted.lock().unwrap().push(args.clone());
            // Advance the mock anchor state as if the tx landed.
            let mut state = self.anchor_state.lock().unwrap();
            state.batch_count += 1;
            state.last_ns_range_end = args.ns_range_end;
            Ok(self.return_digest.clone())
        }
    }

    fn swarm() -> SwarmId {
        SwarmId::from_bytes(&[0x42; 16]).unwrap()
    }

    fn fixture_receipt(monotonic_ns: u64, seed: u8) -> Receipt {
        ReceiptBuilder::new()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(swarm())
            .actor({
                let mut bytes = [0u8; 16];
                bytes[0] = seed;
                AgentId::from_bytes(&bytes).unwrap()
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
    async fn seal_batch_submits_args_and_returns_digest() {
        let client = MockClient::new();
        let expected_digest = client.return_digest.clone();
        let sealer = SuiSealer::new_for_tests(Box::new(client), vec![0xCC; 64], swarm());

        let receipts = vec![fixture_receipt(100, 1), fixture_receipt(200, 2)];
        let batch = sealer.seal_batch(&receipts).await.unwrap();

        assert_eq!(batch.commitment_id, expected_digest);
        assert_eq!(batch.ns_range, (100, 200));
        assert_eq!(batch.leaves.len(), 2);
    }

    #[tokio::test]
    async fn seal_batch_rejects_empty() {
        let sealer = SuiSealer::new_for_tests(Box::new(MockClient::new()), vec![0xCC; 64], swarm());
        let err = sealer.seal_batch(&[]).await.unwrap_err();
        assert!(matches!(err, SealError::EmptyBatch));
    }

    #[tokio::test]
    async fn seal_batch_propagates_transient_client_error() {
        let client = MockClient::new();
        *client.fail_with.lock().unwrap() =
            Some(AnchorBackendError::RpcTransient("RPC down".into()));
        let sealer = SuiSealer::new_for_tests(Box::new(client), vec![0xCC; 64], swarm());

        let err = sealer
            .seal_batch(&[fixture_receipt(1, 1)])
            .await
            .unwrap_err();
        assert!(matches!(err, SealError::Transient(_)));
    }

    #[tokio::test]
    async fn seal_batch_propagates_on_chain_abort() {
        let client = MockClient::new();
        *client.fail_with.lock().unwrap() = Some(AnchorBackendError::OnChainAbort {
            code: Some(9),
            detail: "ESealerKeyMismatch".into(),
        });
        let sealer = SuiSealer::new_for_tests(Box::new(client), vec![0xCC; 64], swarm());

        let err = sealer
            .seal_batch(&[fixture_receipt(1, 1)])
            .await
            .unwrap_err();
        match err {
            SealError::Permanent(msg) => {
                assert!(msg.contains("9") && msg.contains("ESealerKeyMismatch"))
            }
            other => panic!("expected Permanent, got {other:?}"),
        }
    }
}
