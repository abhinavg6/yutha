//! Mapping from `azure_core::Error` → [`SignerError`].
//!
//! Implements [RFC 0017 §3.4 — Standardised error mapping](../../../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping).
//! The mapping is "what should the caller do?" first, "what did the
//! backend say?" second:
//!
//! | Azure response                                  | [`SignerError`] variant            | Retryable? |
//! |-------------------------------------------------|------------------------------------|------------|
//! | 401 / 403 (auth, IAM)                           | [`SignerError::BackendRejected`]   | No         |
//! | 404 (key / version missing)                     | [`SignerError::BackendRejected`]   | No         |
//! | 400 (bad request — wrong tier, wrong alg)       | [`SignerError::BackendRejected`]   | No         |
//! | 429 (throttled)                                 | [`SignerError::BackendUnavailable`]| Yes        |
//! | 503 / 504 / 408 (transient)                     | [`SignerError::BackendUnavailable`]| Yes        |
//! | Other 5xx                                       | [`SignerError::BackendUnavailable`]| Yes        |
//! | Transport / TLS / credential-chain exhausted    | [`SignerError::BackendUnavailable`]| Yes        |
//! | Anything else                                   | [`SignerError::Internal`]          | No         |

use azure_core::{error::ErrorKind, http::StatusCode, Error as AzureError};
use yutha_signer::SignerError;

/// Map an `azure_core::Error` to a [`SignerError`].
///
/// `context` is a short tag prepended to the error message so logs can
/// tell apart connect-time / fetch-key-time / sign-time failures.
///
/// The Azure Rust SDK surfaces errors as `azure_core::Error` whose
/// `ErrorKind` discriminates between transport-layer failures
/// (no HTTP status) and service errors (HTTP status carried in
/// `HttpResponse { status, .. }`). RFC 0017 §3.4 says transport
/// failures route to `BackendUnavailable` (retryable); service errors
/// route per their status code.
pub fn map_azure_error(err: AzureError, context: &str) -> SignerError {
    let msg = format!("{context}: {err}");

    if let ErrorKind::HttpResponse { status, .. } = err.kind() {
        return classify_status(*status, msg);
    }

    // No HTTP status — transport, TLS, credential exhaustion, JSON
    // deserialisation. Be conservative: treat as retryable. The
    // substrate's caller has the retry budget; this matches RFC 0017
    // §3.4's "transport-shaped failures are BackendUnavailable" rule.
    SignerError::BackendUnavailable(msg)
}

fn classify_status(status: StatusCode, msg: String) -> SignerError {
    // azure_core::http::StatusCode is the standard HTTP status enum with
    // named variants. We match the cases that affect the operator's
    // retry decision; everything else falls through to Internal.
    match status {
        StatusCode::Unauthorized
        | StatusCode::Forbidden
        | StatusCode::NotFound
        | StatusCode::BadRequest => SignerError::BackendRejected(msg),
        StatusCode::TooManyRequests
        | StatusCode::ServiceUnavailable
        | StatusCode::GatewayTimeout
        | StatusCode::RequestTimeout => SignerError::BackendUnavailable(msg),
        other => {
            // Catch the broader 5xx range here without enumerating
            // every variant — u16 conversion is the portable path.
            let code: u16 = other.into();
            if (500..=599).contains(&code) {
                SignerError::BackendUnavailable(msg)
            } else {
                SignerError::Internal(msg)
            }
        }
    }
}
