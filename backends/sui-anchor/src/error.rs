//! Error types for the Sui-anchor backend.
//!
//! Distinguishes transient (RPC down, retry) from permanent (signature
//! mismatch, package not found) failures so the [`crate::driver::AnchorDriver`]
//! cadence loop can decide between backoff-and-retry and alert-the-operator.

use thiserror::Error;
use yutha_receipt::SealError;

/// Result alias bound to [`AnchorBackendError`].
pub type Result<T> = std::result::Result<T, AnchorBackendError>;

/// Errors the Sui-anchor backend surfaces. Mapped onto
/// [`yutha_receipt::SealError`] at the [`crate::sealer::SuiSealer`] →
/// [`yutha_receipt::Sealer`] boundary.
#[derive(Debug, Error)]
pub enum AnchorBackendError {
    /// Sui RPC connection / wire-level failure. Retryable.
    #[error("sui rpc transient: {0}")]
    RpcTransient(String),

    /// On-chain `commit_batch` aborted (e.g. `ESealerKeyMismatch`,
    /// `ENsRangeNotMonotonic`). Carries the abort code if parsed.
    /// Permanent — operator must investigate.
    #[error("on-chain abort code {code:?}: {detail}")]
    OnChainAbort {
        /// Move abort code per `/spec/verifiability/sui-anchoring.md` §5.5.
        code: Option<u64>,
        /// Human-readable detail extracted from the tx response.
        detail: String,
    },

    /// Failed to read the `SwarmAnchor` shared object (object missing,
    /// wrong shape, etc.). Permanent.
    #[error("swarm-anchor read failed: {0}")]
    SwarmAnchorRead(String),

    /// Failed to load or parse the sealer key.
    #[error("sealer key error: {0}")]
    SealerKey(String),

    /// Configuration error (missing flag, malformed object id, etc.).
    #[error("config error: {0}")]
    Config(String),

    /// Canonical preimage construction failed at the `yutha-receipt`
    /// layer. Propagates [`yutha_receipt::ReceiptError::BatchInvalid`]
    /// from the underlying batch.
    #[error("preimage construction: {0}")]
    Preimage(String),

    /// Wrapper for `yutha-crypto` errors.
    #[error(transparent)]
    Crypto(#[from] yutha_crypto::CryptoError),
}

impl From<AnchorBackendError> for SealError {
    fn from(e: AnchorBackendError) -> Self {
        match e {
            AnchorBackendError::RpcTransient(msg) => SealError::Transient(msg),
            AnchorBackendError::OnChainAbort { code, detail } => {
                let summary = match code {
                    Some(c) => format!("on-chain abort code {c}: {detail}"),
                    None => format!("on-chain abort: {detail}"),
                };
                SealError::Permanent(summary)
            }
            AnchorBackendError::SwarmAnchorRead(msg) => SealError::Permanent(msg),
            AnchorBackendError::SealerKey(msg) => SealError::Signing(msg),
            AnchorBackendError::Config(msg) => SealError::Permanent(msg),
            AnchorBackendError::Preimage(msg) => SealError::Preimage(msg),
            AnchorBackendError::Crypto(e) => SealError::Signing(e.to_string()),
        }
    }
}
