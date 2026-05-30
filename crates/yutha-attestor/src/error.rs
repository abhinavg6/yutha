//! Error type for [`Attestor`](crate::Attestor) implementations.

use thiserror::Error;

/// Errors an [`Attestor`](crate::Attestor) implementation may return.
///
/// Variants are designed to let the admission handler distinguish:
/// - **Permanent rejections** (`Malformed`, `Rejected`) → the
///   registration request fails with `PERMISSION_DENIED`; an
///   `agent.register.deny` receipt is emitted; the client should not
///   retry without a different credential.
/// - **Transient unavailability** (`TrustRootUnavailable`) → the
///   registration request fails with `UNAVAILABLE`; the client MAY
///   retry; no deny receipt is emitted (because no verdict was
///   reached).
/// - **Yutha-side bugs** (`Internal`) → the registration request
///   fails with `INTERNAL`; an `agent.register.deny` receipt is
///   emitted (the verdict was "deny" even if the cause was internal);
///   the operator should investigate logs.
///
/// # PII safety
///
/// Implementations MUST NOT include the raw credential bytes, claim
/// contents, or any other identifier from the credential in the error
/// message. The operator can correlate Yutha-side rejections with
/// the IdP's audit log via timestamp + claimed_agent_id (which is on
/// the deny receipt's evidence).
#[derive(Debug, Error)]
pub enum AttestorError {
    /// Credential was structurally malformed (wrong format, bad
    /// signature algorithm, JWT failed to parse, ASN.1 decode failed,
    /// etc.). The credential never reached the trust-root check.
    ///
    /// Treated as a permanent rejection by the admission handler.
    #[error("credential malformed: {0}")]
    Malformed(String),

    /// Credential parsed OK but failed validation: bad signature,
    /// expired, wrong audience, subject mismatch, unknown issuer,
    /// trust-root denied. The trust root said "no."
    ///
    /// Treated as a permanent rejection by the admission handler.
    #[error("credential rejected: {0}")]
    Rejected(String),

    /// The IdP-side trust root was unreachable: SPIRE Workload API
    /// socket down, OIDC JWKS endpoint timed out, network partition.
    /// No verdict was reached.
    ///
    /// Distinct from [`AttestorError::Rejected`] because the
    /// admission handler MAY choose to surface a retryable error
    /// code to the client and skip the deny-receipt emission (no
    /// verdict = nothing to record).
    #[error("trust root unavailable: {0}")]
    TrustRootUnavailable(String),

    /// Anything else — typically a Yutha-side bug or unexpected
    /// SDK error from the IdP client library.
    #[error("internal attestor error: {0}")]
    Internal(String),
}
