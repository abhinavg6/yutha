//! Mapping from `google_cloud_kms_v1::Error` → [`SignerError`].
//!
//! Implements [RFC 0017 §3.4 — Standardised error mapping](../../../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping).
//! The mapping is "what should the caller do?" first, "what did the
//! backend say?" second:
//!
//! | gRPC status                              | [`SignerError`] variant            | Retryable? |
//! |------------------------------------------|------------------------------------|------------|
//! | `PERMISSION_DENIED` / `UNAUTHENTICATED`  | [`SignerError::BackendRejected`]   | No         |
//! | `NOT_FOUND` (key/version missing)        | [`SignerError::BackendRejected`]   | No         |
//! | `FAILED_PRECONDITION` (wrong algorithm)  | [`SignerError::BackendRejected`]   | No         |
//! | `UNAVAILABLE`                            | [`SignerError::BackendUnavailable`]| Yes        |
//! | `DEADLINE_EXCEEDED` / transport          | [`SignerError::BackendUnavailable`]| Yes        |
//! | Anything else                            | [`SignerError::Internal`]          | No         |
//!
//! Algorithm-mismatch detected *Yutha-side* (Vault's reported algorithm
//! doesn't match `EC_SIGN_ED25519`) is surfaced as
//! [`SignerError::UnsupportedAlgorithm`] directly from
//! [`crate::signer::GcpKmsSigner::connect`], not from this mapper.

use google_cloud_kms_v1::Error as KmsError;
use yutha_signer::SignerError;

/// Map a `google_cloud_kms_v1::Error` to a [`SignerError`].
///
/// `context` is a short tag prepended to the error message so logs can
/// tell apart connect-time / fetch-key-time / sign-time failures.
///
/// The Google Rust SDK surfaces a structured `Error` whose root cause
/// may be a transport-layer failure, an HTTP status, or a gRPC status.
/// We match on whether the error reports an HTTP status that maps onto
/// one of the well-known gRPC codes; everything else routes through
/// `BackendUnavailable` (retryable transport) or `Internal`.
pub fn map_kms_error(err: KmsError, context: &str) -> SignerError {
    // The Google SDK uses `Error::http_status_code()` to surface a
    // standard HTTP status when the failure came from the wire. gRPC
    // statuses get mapped onto HTTP equivalents by the underlying gax
    // transport (PERMISSION_DENIED -> 403, NOT_FOUND -> 404,
    // FAILED_PRECONDITION -> 400, UNAVAILABLE -> 503, DEADLINE_EXCEEDED
    // -> 504). Treat anything we don't recognise as either retryable
    // (transport-shaped) or internal.
    let msg = format!("{context}: {err}");

    match err.http_status_code() {
        Some(401 | 403 | 404 | 400) => SignerError::BackendRejected(msg),
        Some(503 | 504 | 408 | 429) => SignerError::BackendUnavailable(msg),
        Some(500..=599) => SignerError::BackendUnavailable(msg),
        Some(_) => SignerError::Internal(msg),
        // No HTTP code surfaced — usually transport / connect / TLS.
        // RFC 0017 §3.4 says these are retryable.
        None => SignerError::BackendUnavailable(msg),
    }
}
