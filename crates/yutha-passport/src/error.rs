//! Errors raised by passport operations.

use thiserror::Error;
use yutha_core::{AgentId, CoreError};
use yutha_crypto::CryptoError;

/// Result alias bound to [`PassportError`].
pub type Result<T> = std::result::Result<T, PassportError>;

/// Errors raised by passport construction, storage, or lookup.
#[derive(Debug, Error)]
pub enum PassportError {
    /// The passport's self-signature did not verify against the inlined
    /// public key. Indicates either tampering or a builder bug.
    #[error("passport self-signature invalid")]
    SelfSignatureInvalid,

    /// Required fields missing on a partially-constructed passport.
    #[error("passport missing required field: {0}")]
    MissingField(&'static str),

    /// The passport expired at construction time, or expired in flight.
    #[error("passport expired")]
    Expired,

    /// Attempt to register an AgentId that's already registered.
    #[error("agent already registered: {0}")]
    AlreadyRegistered(AgentId),

    /// Attempt to operate on an agent that isn't registered.
    #[error("agent not found: {0}")]
    NotFound(AgentId),

    /// Attempt to rotate a key without proof of continuity (signature with
    /// the old key over the new passport).
    #[error("key rotation requires continuity signature from previous key")]
    RotationContinuityMissing,

    /// Generic backend error.
    #[error("backend error: {0}")]
    Backend(String),

    /// Crypto-layer error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Core-layer error.
    #[error(transparent)]
    Core(#[from] CoreError),
}
