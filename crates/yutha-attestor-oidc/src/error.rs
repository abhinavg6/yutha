//! Centralised mapping from internal error sources to [`AttestorError`].
//!
//! Implements the spec §9 error-mapping table:
//! [`/spec/identity-keys/attestor-oidc.md` §9](../../../../spec/identity-keys/attestor-oidc.md#9-error-mapping).
//!
//! # Why a centralised helper instead of `From` impls
//!
//! The same `jsonwebtoken::ErrorKind` variant maps to different
//! `AttestorError` variants depending on which step of the verify
//! algorithm raised it. Specifically: `InvalidSignature` is
//! `Rejected("signature verification failed")` from step 5, but
//! `InvalidAudience` from the same underlying library call is
//! `Rejected("audience mismatch")` from step 7 — same library error
//! type, different message, different spec row. A `From` impl can't
//! see the step context; a helper that takes the source error can.
//!
//! # PII rule (spec §9.1)
//!
//! No error message produced by this module may contain:
//!
//! - Any byte of the original credential.
//! - Decoded payload fields (`iss`, `sub`, `aud`, custom claims,
//!   selectors, JWT IDs).
//! - Decoded header fields other than the algorithm name (the alg is
//!   a low-entropy enum, not a subject identifier).
//!
//! All mappings below produce messages that contain only:
//! - The verify-step name.
//! - The algorithm value (where reporting it is unambiguously safe).
//! - Cap / window numeric values.

use jsonwebtoken::errors::ErrorKind;
use yutha_attestor::AttestorError;

/// Map a `jsonwebtoken::errors::Error` from the verify-time
/// `jsonwebtoken::decode` call to the appropriate `AttestorError`
/// variant per spec §9.
///
/// This helper covers the post-signature-verify error rows. The
/// pre-verify rows (empty credential, header-decode failures,
/// kid-not-found, JWKS-source-unavailable) are produced directly
/// by [`crate::OidcAttestor::verify`] without going through this
/// function — they don't have a `jsonwebtoken::Error` source.
pub fn map_oidc_error(err: jsonwebtoken::errors::Error) -> AttestorError {
    // The match below names only variants we've verified exist in the
    // pinned jsonwebtoken (`^10`) version. ErrorKind is `#[non_exhaustive]`
    // (and has churned across 9.x → 10.x), so naming speculative
    // variants risks tying compilation to whatever surface a future
    // bump happens to expose. Everything else falls through to the
    // catch-all → Malformed("token validation failed"), which is the
    // conservative classification (admission rejects but doesn't
    // return a retryable code that would mask a substrate bug).
    //
    // Mirrors the SPIFFE crate's defensive posture in
    // `crates/yutha-attestor-spiffe/src/error.rs::map_jwt_token_error`.
    match err.kind() {
        // Signature verification failed. Spec §9 row "JWS signature
        // verification failure" → Rejected. Message MUST NOT mention
        // which key was tried; just the verb.
        ErrorKind::InvalidSignature => {
            AttestorError::Rejected("signature verification failed".to_string())
        }

        // The library raises `InvalidToken` for any JWS parse failure
        // at decode-time (vs. decode_header which we call first; that
        // catches most parse problems earlier). Reaches here on
        // payload-segment base64 / utf8 issues mid-decode.
        ErrorKind::InvalidToken => {
            AttestorError::Malformed("not a JWS compact serialization".to_string())
        }

        // Spec §9 "iss does not equal expected_issuer" → Rejected.
        ErrorKind::InvalidIssuer => AttestorError::Rejected("issuer mismatch".to_string()),

        // Spec §9 "aud does not contain expected_audience" → Rejected.
        ErrorKind::InvalidAudience => AttestorError::Rejected("audience mismatch".to_string()),

        // Spec §9 "exp ≤ now()" → Rejected. jsonwebtoken's name for
        // this variant is `ExpiredSignature`; the underlying check is
        // exp-versus-now-plus-leeway.
        ErrorKind::ExpiredSignature => AttestorError::Rejected("credential expired".to_string()),

        // Spec §9 "nbf > now() + clock_skew_tolerance" → Rejected.
        // `ImmatureSignature` is jsonwebtoken's name for "nbf in the
        // future".
        ErrorKind::ImmatureSignature => AttestorError::Rejected("nbf in the future".to_string()),

        // Spec §9 "Missing exp claim" / "Missing aud claim" / etc.
        // → Malformed with the claim name. Safe to expose the claim
        // name (low-entropy enum-like value) but NOT the claim value.
        ErrorKind::MissingRequiredClaim(claim) => {
            AttestorError::Malformed(format!("payload: missing/invalid {claim}"))
        }

        // Catch-all per the rationale at the top of this match. Covers
        // base64 / JSON / UTF-8 parse failures, header alg-name issues,
        // key-shape mismatches (`InvalidEcdsaKey` / `InvalidRsaKey` /
        // similar), and any future variants. All map to Malformed —
        // the credential isn't a JWT we can verify.
        _ => AttestorError::Malformed("token validation failed".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::errors::Error;

    fn err_with_kind(kind: ErrorKind) -> Error {
        // jsonwebtoken's Error is constructed via `From<ErrorKind>`.
        kind.into()
    }

    #[test]
    fn invalid_signature_maps_to_rejected() {
        let err = map_oidc_error(err_with_kind(ErrorKind::InvalidSignature));
        match err {
            AttestorError::Rejected(msg) => {
                assert!(msg.contains("signature"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn invalid_issuer_maps_to_rejected_issuer_mismatch() {
        let err = map_oidc_error(err_with_kind(ErrorKind::InvalidIssuer));
        match err {
            AttestorError::Rejected(msg) => {
                assert_eq!(msg, "issuer mismatch");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn invalid_audience_maps_to_rejected_audience_mismatch() {
        let err = map_oidc_error(err_with_kind(ErrorKind::InvalidAudience));
        match err {
            AttestorError::Rejected(msg) => {
                assert_eq!(msg, "audience mismatch");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn expired_signature_maps_to_rejected_credential_expired() {
        let err = map_oidc_error(err_with_kind(ErrorKind::ExpiredSignature));
        match err {
            AttestorError::Rejected(msg) => {
                assert_eq!(msg, "credential expired");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn immature_signature_maps_to_rejected_nbf_future() {
        let err = map_oidc_error(err_with_kind(ErrorKind::ImmatureSignature));
        match err {
            AttestorError::Rejected(msg) => {
                assert_eq!(msg, "nbf in the future");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn missing_required_claim_maps_to_malformed_with_claim_name() {
        let err = map_oidc_error(err_with_kind(ErrorKind::MissingRequiredClaim(
            "exp".to_string(),
        )));
        match err {
            AttestorError::Malformed(msg) => {
                assert!(msg.contains("missing/invalid"));
                assert!(msg.contains("exp"));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn invalid_token_maps_to_malformed_jws() {
        let err = map_oidc_error(err_with_kind(ErrorKind::InvalidToken));
        match err {
            AttestorError::Malformed(msg) => {
                assert!(msg.contains("not a JWS"));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn no_message_leaks_pii() {
        // PII-rule spot check: a small sampling of variants — none
        // should produce messages containing claim-shaped strings
        // (looking for substrings that would indicate value leakage,
        // not just the safe variant tag).
        let pii_like = ["user@example.com", "spiffe://", "okta", "sub_"];
        for kind in [
            ErrorKind::InvalidSignature,
            ErrorKind::InvalidIssuer,
            ErrorKind::InvalidAudience,
            ErrorKind::ExpiredSignature,
            ErrorKind::ImmatureSignature,
        ] {
            let err = map_oidc_error(err_with_kind(kind));
            let msg = err.to_string();
            for needle in &pii_like {
                assert!(
                    !msg.contains(needle),
                    "error message leaked PII-shaped substring {needle:?}: {msg}"
                );
            }
        }
    }
}
