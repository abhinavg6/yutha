//! Errors raised by the registry.

use thiserror::Error;
use yutha_core::{CoreError, SwarmId};
use yutha_passport::PassportError;

/// Result type bound to [`RegistryError`].
pub type Result<T> = std::result::Result<T, RegistryError>;

/// Errors raised by the registry.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Topology and admission-policy variant disagree (e.g., CLOSED mode
    /// with an OpenPolicy admission). Set at swarm creation; once a
    /// registry is up, this should be unreachable.
    #[error("topology / admission-policy mismatch")]
    TopologyInconsistent,

    /// Admission denied by the topology's policy.
    #[error("admission denied: {0}")]
    AdmissionDenied(String),

    /// Sybil-resistance check failed.
    #[error("sybil resistance check failed: {0}")]
    SybilCheckFailed(String),

    /// Attempt to register into a different swarm than this registry serves.
    #[error("wrong swarm: registry serves {expected}, passport is for {actual}")]
    SwarmMismatch {
        /// Swarm id the registry serves.
        expected: SwarmId,
        /// Swarm id the passport declared.
        actual: SwarmId,
    },

    /// Topology mutation attempted on a live registry.
    #[error("topology is immutable; create a new swarm to change it")]
    TopologyImmutable,

    /// Passport-layer error.
    #[error(transparent)]
    Passport(#[from] PassportError),

    /// Receipt-store error encountered while producing the admission
    /// receipt.
    #[error(transparent)]
    Receipt(#[from] yutha_receipt::ReceiptError),

    /// Core-layer error.
    #[error(transparent)]
    Core(#[from] CoreError),

    /// Backend error.
    #[error("backend: {0}")]
    Backend(String),
}
