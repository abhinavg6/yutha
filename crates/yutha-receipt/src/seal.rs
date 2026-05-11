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
}

impl SealStatus {
    /// Construct an unsealed status.
    pub fn unsealed() -> Self {
        Self {
            state: SealState::Unsealed,
            batch_root: None,
            merkle_path: vec![],
            sealed_at: None,
        }
    }

    /// Construct a sealed status with the supplied root and path.
    pub fn sealed(batch_root: Hash, merkle_path: Vec<Hash>, sealed_at: Timestamp) -> Self {
        Self {
            state: SealState::Sealed,
            batch_root: Some(batch_root),
            merkle_path,
            sealed_at: Some(sealed_at),
        }
    }
}

impl Default for SealStatus {
    fn default() -> Self {
        Self::unsealed()
    }
}
