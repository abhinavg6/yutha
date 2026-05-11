//! Errors for the transport layer.

use thiserror::Error;
use yutha_core::CoreError;
use yutha_crypto::CryptoError;

/// Result type for transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Substrate-level envelope-rejection reasons. Mirrors the
/// `EnvelopeError.Reason` enum in the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Signature verification failed.
    SignatureInvalid,
    /// Spec version is unknown to this receiver.
    UnknownSpecVersion,
    /// Replay detected (nonce / epoch / TTL check).
    ReplayDetected,
    /// Envelope expired before processing.
    Expired,
    /// Malformed envelope.
    Malformed,
    /// Performative is unknown.
    UnknownPerformative,
    /// Recipient could not be resolved.
    RecipientUnknown,
    /// Capability denied (cross-swarm / external send).
    CapabilityDenied,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Transport-level error.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Envelope was rejected at substrate validation.
    #[error("envelope rejected: {0}")]
    EnvelopeRejected(EnvelopeError),

    /// Failed to deliver to recipient.
    #[error("delivery failed: {0}")]
    Delivery(String),

    /// Receive timed out.
    #[error("receive timeout")]
    Timeout,

    /// Backpressure: queue full.
    #[error("backpressure")]
    Backpressure,

    /// Backend I/O error.
    #[error("backend: {0}")]
    Backend(String),

    /// Receipt-store error encountered while appending an
    /// envelope-related receipt.
    #[error(transparent)]
    Receipt(#[from] yutha_receipt::ReceiptError),

    /// Crypto error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Core error.
    #[error(transparent)]
    Core(#[from] CoreError),
}
