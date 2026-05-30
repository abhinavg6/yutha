//! Mapping from `vaultrs::error::ClientError` → [`SignerError`].
//!
//! Implements [RFC 0017 §3.4 — Standardised error mapping](../../../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping).
//! The mapping is "what should the caller do?" first, "what did the backend
//! say?" second:
//!
//! | Vault response              | [`SignerError`] variant            | Retryable? |
//! |-----------------------------|------------------------------------|------------|
//! | 401 / 403 (auth failure)    | [`SignerError::BackendRejected`]   | No         |
//! | 404 (key missing)           | [`SignerError::BackendRejected`]   | No         |
//! | 5xx                         | [`SignerError::BackendUnavailable`]| Yes        |
//! | Network / TLS / timeout     | [`SignerError::BackendUnavailable`]| Yes        |
//! | URL parse / config invalid  | [`SignerError::Internal`]          | No         |
//! | Anything else               | [`SignerError::Internal`]          | No         |
//!
//! Algorithm-mismatch surfaces from [`crate::signer::VaultSigner::connect`]
//! directly as [`SignerError::UnsupportedAlgorithm`], not from this mapper —
//! it's a Yutha-side check on Vault's `key_type` response, not a Vault HTTP
//! error.

use vaultrs::error::ClientError;
use yutha_signer::SignerError;

/// Map a `vaultrs::ClientError` to a [`SignerError`].
///
/// Per RFC 0015 §6, the trait's caller should be able to distinguish
/// "back off and retry" from "alert an operator." This mapping makes that
/// decision once, in one place, so all `VaultSigner` call sites pick up
/// the same posture.
///
/// `context` is a short tag prepended to the error message so logs can
/// tell apart `connect`-time failures from `sign`-time failures from
/// `fetch-key`-time failures.
pub fn map_client_error(err: ClientError, context: &str) -> SignerError {
    match &err {
        // vaultrs surfaces HTTP errors with the status code attached.
        // 401/403 = auth rejected (don't retry without operator action).
        // 404    = key missing (don't retry — operator must provision).
        // 5xx    = backend trouble (retry-friendly).
        ClientError::APIError { code, errors: _ } => {
            let msg = format!("{context}: vault returned HTTP {code}: {err}");
            match *code {
                401 | 403 | 404 => SignerError::BackendRejected(msg),
                500..=599 => SignerError::BackendUnavailable(msg),
                _ => SignerError::Internal(msg),
            }
        }

        // Network-layer / connection-pool / TLS failures. The contract says
        // these are retry-friendly, so route to BackendUnavailable.
        ClientError::RestClientError { .. } => {
            SignerError::BackendUnavailable(format!("{context}: vault transport error: {err}"))
        }

        // Anything else — config parse problems, response deserialization
        // failures, etc. — is a Yutha-side problem, not a backend signal.
        _ => SignerError::Internal(format!("{context}: {err}")),
    }
}
