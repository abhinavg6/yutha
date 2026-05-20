//! [`SealStatus`] — Merkle-batch sealing for the verifiable tier.
//!
//! Mirrors `SealStatus` from
//! [`/spec/receipt/receipt-v1.proto`](../../../spec/receipt/receipt-v1.proto).
//! Sealing is optional at Core/Full and required at Verifiable. UNSEALED
//! receipts are fully valid; SEALED adds Merkle-path inclusion proofs.

use yutha_core::{Hash, Timestamp};

/// Coarse seal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SealState {
    /// Receipt has not yet been included in a Merkle batch.
    Unsealed,
    /// Receipt is sealed in a Merkle batch with a signed root.
    Sealed,
}

/// Sealing details.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SealStatus {
    /// Coarse state.
    pub state: SealState,
    /// When sealed, the Merkle root of the batch.
    pub batch_root: Option<Hash>,
    /// Path from this receipt to `batch_root`. The path's siblings let an
    /// external verifier check inclusion without revealing the rest of the
    /// batch.
    pub merkle_path: Vec<Hash>,
    /// When the seal happened.
    pub sealed_at: Option<Timestamp>,
    /// Sui transaction digest of the `commit_batch` transaction that
    /// anchored this receipt's batch on-chain. 32 raw bytes. Present only
    /// when sealed by a [`Sealer`] that targets a verifiability backend
    /// (currently the `SuiSealer` from `yutha-anchor-sui`). Sealing via
    /// `LocalSealer` leaves this `None` per RFC 0014.
    pub on_chain_tx_digest: Option<Vec<u8>>,
    /// Sui shared-object id of the `SwarmAnchor` object holding the rolling
    /// commitment history for this swarm. 32 raw bytes. Populated together
    /// with [`Self::on_chain_tx_digest`]. With both present plus
    /// [`Self::merkle_path`], a verifier can do an end-to-end inclusion
    /// check without external metadata.
    pub swarm_anchor_object_id: Option<Vec<u8>>,
}

impl SealStatus {
    /// Construct an unsealed status.
    pub fn unsealed() -> Self {
        Self {
            state: SealState::Unsealed,
            batch_root: None,
            merkle_path: vec![],
            sealed_at: None,
            on_chain_tx_digest: None,
            swarm_anchor_object_id: None,
        }
    }

    /// Construct a sealed status with the supplied root and path. Used by
    /// the [`LocalSealer`] (no on-chain anchor) and by tests.
    pub fn sealed(batch_root: Hash, merkle_path: Vec<Hash>, sealed_at: Timestamp) -> Self {
        Self {
            state: SealState::Sealed,
            batch_root: Some(batch_root),
            merkle_path,
            sealed_at: Some(sealed_at),
            on_chain_tx_digest: None,
            swarm_anchor_object_id: None,
        }
    }

    /// Construct a sealed status with the supplied root, path, AND the
    /// Sui on-chain anchor coordinates. Used by `SuiSealer`.
    pub fn sealed_with_anchor(
        batch_root: Hash,
        merkle_path: Vec<Hash>,
        sealed_at: Timestamp,
        on_chain_tx_digest: Vec<u8>,
        swarm_anchor_object_id: Vec<u8>,
    ) -> Self {
        Self {
            state: SealState::Sealed,
            batch_root: Some(batch_root),
            merkle_path,
            sealed_at: Some(sealed_at),
            on_chain_tx_digest: Some(on_chain_tx_digest),
            swarm_anchor_object_id: Some(swarm_anchor_object_id),
        }
    }
}

impl Default for SealStatus {
    fn default() -> Self {
        Self::unsealed()
    }
}
