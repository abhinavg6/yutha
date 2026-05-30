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

    /// The configured `Attestor` (RFC 0016) rejected the external
    /// credential on a registration request. A `agent.register.deny`
    /// receipt was emitted with the same `attestor_id` + `reason`.
    /// The gRPC layer maps this to `PERMISSION_DENIED`.
    #[error("attestation denied by attestor `{attestor_id}`: {reason}")]
    AttestationDenied {
        /// `Attestor::id()` of the Attestor that rejected.
        attestor_id: String,
        /// Operator-facing reason from `AttestorError::{Malformed,Rejected,Internal}`.
        reason: String,
    },

    /// The configured `Attestor` (RFC 0016) could not reach its trust
    /// root (SPIRE socket down, OIDC JWKS endpoint timed out). No
    /// verdict was reached, so NO deny receipt was emitted. The gRPC
    /// layer maps this to `UNAVAILABLE` so the client knows to retry.
    #[error("attestation trust root unavailable for `{attestor_id}`: {reason}")]
    AttestationUnavailable {
        /// `Attestor::id()` of the Attestor that couldn't reach its trust root.
        attestor_id: String,
        /// Operator-facing reason from `AttestorError::TrustRootUnavailable`.
        reason: String,
    },

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
