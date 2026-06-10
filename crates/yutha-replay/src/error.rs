//! Error type for the replay engine.

use thiserror::Error;

/// Errors raised by [`crate::ReplaySession`].
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Underlying receipt-store call failed. Wraps
    /// [`yutha_receipt::ReceiptError`].
    #[error("receipt store: {0}")]
    Receipt(#[from] yutha_receipt::ReceiptError),

    /// Underlying cedar-plus call failed. Stored as a string because
    /// the upstream error type isn't `Send + Sync` to the degree this
    /// boundary needs.
    #[error("constitution layer: {0}")]
    CedarPlus(String),

    /// A receipt in the input window was malformed for replay —
    /// missing required evidence, unparseable timestamp, etc.
    /// Carries the receipt's content-address for grep-back.
    #[error("invalid input receipt {receipt_id}: {detail}")]
    InvalidInputReceipt {
        /// Hex-encoded content-address of the offending receipt.
        receipt_id: String,
        /// What went wrong.
        detail: String,
    },

    /// The session's signer call failed.
    #[error("signer: {0}")]
    Signer(String),

    /// Generic backend / I/O failure.
    #[error("replay backend: {0}")]
    Backend(String),
}

/// Result alias for [`ReplayError`].
pub type Result<T> = std::result::Result<T, ReplayError>;
