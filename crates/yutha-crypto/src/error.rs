//! Error types for cryptographic operations.

use thiserror::Error;
use yutha_core::CoreError;

/// Result alias bound to [`CryptoError`].
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Errors raised by cryptographic primitives.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A key was malformed or had the wrong length.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// A signature was malformed or had the wrong length.
    #[error("invalid signature format: {0}")]
    InvalidSignature(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// Hash computation failed (should be unreachable in practice).
    #[error("hash error: {0}")]
    Hash(String),

    /// Wrapper for upstream `yutha-core` errors.
    #[error(transparent)]
    Core(#[from] CoreError),
}
