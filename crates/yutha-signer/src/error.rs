//! Error type for [`Signer`](crate::Signer) implementations.

use thiserror::Error;

/// Errors a [`Signer`](crate::Signer) implementation may return.
///
/// Variants are designed to let callers distinguish between transient
/// (retryable) and permanent (don't-retry) failures, and between
/// algorithm-mismatch errors (surfaced at construction, not per-call) and
/// per-call errors.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The backend was reachable but rejected the signing request (auth,
    /// key disabled, key not found, quota exceeded, …). Retrying without
    /// intervention will not help.
    #[error("signer backend rejected: {0}")]
    BackendRejected(String),

    /// The backend was unreachable or returned a transient error.
    /// Retrying MAY help. Implementations SHOULD retry transient errors
    /// internally before surfacing this; surface this variant when the
    /// implementation's own retry budget is exhausted or when the caller
    /// is expected to make the retry decision (e.g., during startup,
    /// where the agent's process supervisor might restart the agent
    /// rather than have it loop).
    #[error("signer backend unavailable: {0}")]
    BackendUnavailable(String),

    /// The wrapped key uses an algorithm Yutha does not support.
    /// Surfaced at construction time, not per-call. Included in this enum
    /// so construction errors and call errors share a type.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Anything else.
    #[error("internal signer error: {0}")]
    Internal(String),
}
