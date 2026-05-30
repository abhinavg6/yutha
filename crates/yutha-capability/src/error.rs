//! Errors raised by capability operations.

use thiserror::Error;
use yutha_core::{CoreError, Hash};
use yutha_crypto::CryptoError;

/// Result alias bound to [`CapabilityError`].
pub type Result<T> = std::result::Result<T, CapabilityError>;

/// Errors raised by capability construction, storage, or checks.
#[derive(Debug, Error)]
pub enum CapabilityError {
    /// The capability's issuer signature did not verify.
    #[error("issuer signature invalid")]
    IssuerSignatureInvalid,

    /// Required field missing.
    #[error("capability missing required field: {0}")]
    MissingField(&'static str),

    /// The capability is outside its validity window.
    #[error("capability expired or not yet valid")]
    OutOfValidityWindow,

    /// The capability chain exceeds the configured maximum depth.
    #[error("attenuation chain depth {actual} exceeds maximum {max}")]
    ChainTooDeep {
        /// Observed depth.
        actual: u32,
        /// Configured maximum.
        max: u32,
    },

    /// Attenuation attempted to broaden a parent's scope.
    #[error("attenuation cannot broaden parent scope: {detail}")]
    AttenuationBroadens {
        /// Which dimension was broadened.
        detail: String,
    },

    /// Parent capability referenced does not exist.
    #[error("parent capability not found: {0}")]
    ParentNotFound(Hash),

    /// Capability has been revoked.
    #[error("capability revoked")]
    Revoked,

    /// The capability's subject (the agent who would hold or use the
    /// cap) is currently quarantined per RFC 0013 §4.2. Returned by
    /// `issue` / `attenuate` when minting would hand a fresh cap to a
    /// quarantined agent; the `check` path expresses the same
    /// condition as a `CheckOutcome::deny` instead so the deny still
    /// rides on a `capability.check.deny` receipt.
    #[error("capability subject is quarantined: {0}")]
    SubjectQuarantined(yutha_core::AgentId),

    /// Generic backend error.
    #[error("backend error: {0}")]
    Backend(String),

    /// Crypto-layer error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Core-layer error.
    #[error(transparent)]
    Core(#[from] CoreError),

    /// The injected [`yutha_signer::Signer`] failed to produce a signature.
    /// Same posture as `PassportError::Signer` — string-wrapped to keep
    /// this error type from taking a hard dep on the signer error variants.
    #[error("signer failed: {0}")]
    Signer(String),
}
