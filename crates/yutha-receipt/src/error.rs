//! Error types for the receipt store.

use thiserror::Error;
use yutha_core::{CoreError, Hash};
use yutha_crypto::CryptoError;

/// Result alias bound to [`ReceiptError`].
pub type Result<T> = std::result::Result<T, ReceiptError>;

/// Errors raised by the receipt store and its trait implementations.
#[derive(Debug, Error)]
pub enum ReceiptError {
    /// The receipt's content-address (recomputed) did not match the claimed
    /// receipt_id. This is structural tamper detection.
    #[error("content-address mismatch: claimed {claimed} but recomputed {recomputed}")]
    ContentAddressMismatch {
        /// The receipt_id presented by the caller / store.
        claimed: Hash,
        /// The recomputed hash of the canonical serialization.
        recomputed: Hash,
    },

    /// One or more required signatures failed verification.
    #[error("signature verification failed: {detail}")]
    SignatureFailed {
        /// Human-readable detail.
        detail: String,
    },

    /// Required signature role missing (e.g., no actor signature).
    #[error("required signature role missing: {role:?}")]
    MissingSignatureRole {
        /// Which role was missing.
        role: crate::signing::SignatureRole,
    },

    /// Signature ordering convention violated. Per spec rationale §3, the
    /// canonical order is ACTOR → CONTROL_PLANE → SUPERVISOR → ATTESTATION
    /// → BATCH_ROOT.
    #[error("signature ordering invalid: {detail}")]
    SignatureOrderInvalid {
        /// What went wrong.
        detail: String,
    },

    /// Caller attempted to mutate or delete an existing receipt; the store
    /// is append-only.
    #[error("operation forbidden: receipt store is append-only")]
    AppendOnly,

    /// Receipt with the given ID was not found.
    #[error("receipt not found: {0}")]
    NotFound(Hash),

    /// The receipt's actor is not registered with the passport resolver —
    /// no public key to verify the actor signature against. Stricter than
    /// SignatureFailed because the failure is at resolution, not crypto.
    #[error("actor not resolvable: {0}")]
    ActorNotResolvable(yutha_core::AgentId),

    /// The passport resolver itself failed (backend I/O or similar).
    /// Distinguished from ActorNotResolvable so callers can react to
    /// transient errors differently from policy denials.
    #[error("passport resolver error: {0}")]
    PassportResolver(String),

    /// A query parameter was out of range or malformed.
    #[error("invalid query: {0}")]
    InvalidQuery(String),

    /// Backend-specific I/O failure.
    #[error("backend error: {0}")]
    Backend(String),

    /// A batch of receipts handed to the [`crate::sealer::Sealer`] or
    /// the Merkle builder was malformed — empty, contained duplicate
    /// receipt_ids, etc. Returned at construction time before any
    /// network or filesystem state is mutated.
    #[error("invalid batch: {0}")]
    BatchInvalid(String),

    /// Wrapper for `yutha-crypto` errors.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Wrapper for `yutha-core` errors.
    #[error(transparent)]
    Core(#[from] CoreError),
}
