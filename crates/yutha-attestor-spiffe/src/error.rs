//! Error mapping from internal SPIFFE-verification failures to
//! [`AttestorError`](yutha_attestor::AttestorError).
//!
//! Implements [`attestor-spiffe.md` §9](../../../spec/identity-keys/attestor-spiffe.md#9-error-mapping)
//! — the table that pins which [`JwtSvidError`] variant maps to which
//! [`AttestorError`] variant + message shape. Centralised here so no
//! caller can accidentally leak a credential field via an ad-hoc
//! `format!`.

use jsonwebtoken::errors::ErrorKind;
use spiffe::JwtSvidError;
use yutha_attestor::AttestorError;

/// Translate a [`JwtSvidError`] from `spiffe::JwtSvid::parse_and_validate`
/// into a Yutha [`AttestorError`] per the spec's §9 mapping table.
///
/// The non-exhaustive nature of `JwtSvidError` is handled by the
/// catch-all `_` arm landing in [`AttestorError::Internal`] — a future
/// SDK release adding a new variant we don't know about surfaces as
/// "unexpected" rather than being silently misclassified.
///
/// # PII rule
///
/// The returned [`AttestorError`]'s message contains:
///   - the spec-pinned message string for the matched variant;
///   - for `BundleSourceError`, the underlying error's `Display`
///     (which originates in the [`crate::source::BundleCache`] and is
///     already redaction-safe — see `source.rs`);
///   - **NOT** the decoded payload, subject identifier, audience
///     value, or any other field from the credential.
pub fn map_spiffe_error(err: JwtSvidError) -> AttestorError {
    match err {
        // --- Malformed: structural / encoding failures, header issues ---
        // The credential is shaped wrong; an honest client that
        // believes it's holding a JWT-SVID would still fail.
        JwtSvidError::InvalidJwtFormat => {
            AttestorError::Malformed("not a JWS compact serialization".to_string())
        }
        JwtSvidError::InvalidBase64 => {
            AttestorError::Malformed("JWT header/claims base64url decode failed".to_string())
        }
        JwtSvidError::InvalidJson(_) => AttestorError::Malformed("payload not JSON".to_string()),
        JwtSvidError::MissingKeyId => AttestorError::Malformed("header: missing kid".to_string()),
        JwtSvidError::InvalidTyp => AttestorError::Malformed("header: unsupported typ".to_string()),
        JwtSvidError::UnsupportedAlgorithm => {
            AttestorError::Malformed("header: unsupported alg".to_string())
        }
        JwtSvidError::BackendUnsupportedAlgorithm(_) => {
            // Algorithm is valid for JWT-SVID per the SPIFFE spec but
            // not implemented in the verification backend we built
            // with. Operator-visible distinction from
            // UnsupportedAlgorithm doesn't help the spec contract —
            // both reduce to "this credential's alg is not one we'll
            // verify", which spec §9 classifies as Malformed.
            AttestorError::Malformed("header: unsupported alg".to_string())
        }
        JwtSvidError::InvalidSubject(_) => {
            AttestorError::Malformed("sub is not a SPIFFE ID".to_string())
        }
        JwtSvidError::InvalidAuthorityJwk(_) => AttestorError::Malformed(
            "authority JWK in the trust bundle could not be parsed".to_string(),
        ),

        // --- Rejected: shape was fine, validation failed ---
        // The credential is well-formed but does not pass policy
        // (bad signature, wrong audience, expired, etc.).
        JwtSvidError::InvalidExpiration => {
            AttestorError::Rejected("credential expired".to_string())
        }
        JwtSvidError::InvalidAudience(_, _) => {
            AttestorError::Rejected("audience mismatch".to_string())
        }
        JwtSvidError::BundleNotFound(_) => {
            AttestorError::Rejected("trust domain not in bundle".to_string())
        }
        JwtSvidError::AuthorityNotFound(_) => {
            AttestorError::Rejected("kid not found in trust bundle".to_string())
        }
        JwtSvidError::InvalidToken(inner) => map_jwt_token_error(inner.kind()),

        // --- TrustRootUnavailable: source-side fault ---
        // The bundle source the verify path consulted reported a
        // failure that's distinct from "credential is bad". Operators
        // see UNAVAILABLE / 503 at the gRPC layer instead of
        // PERMISSION_DENIED.
        JwtSvidError::BundleSourceError(inner) => {
            AttestorError::TrustRootUnavailable(format!("bundle source error: {inner}"))
        }

        // --- Internal: configuration / build-time fault ---
        // Should be unreachable at runtime: the crate enables
        // `jwt-verify-rust-crypto` so the spiffe SDK's offline
        // verifier IS compiled in. If we hit this, the Cargo.toml
        // feature set has drifted.
        JwtSvidError::JwtVerifyNotEnabled => AttestorError::Internal(
            "offline JWT verification backend not enabled in this build \
             — yutha-attestor-spiffe Cargo.toml should enable the \
             `jwt-verify-rust-crypto` feature of the spiffe crate"
                .to_string(),
        ),

        // --- Forward-compat fallback ---
        // `JwtSvidError` is `#[non_exhaustive]`; new variants land
        // here. The `Internal` route surfaces "we hit an unknown
        // error category" without leaking the Display of the new
        // variant (which we can't audit ahead of time for PII).
        other => AttestorError::Internal(format!(
            "unexpected SPIFFE SDK error variant: {}",
            other_variant_tag(&other),
        )),
    }
}

/// Map the inner [`jsonwebtoken::errors::ErrorKind`] that's packaged
/// inside [`JwtSvidError::InvalidToken`] to a spec §9 row.
///
/// `spiffe::JwtSvid::parse_and_validate` delegates exp + audience
/// checks to `jsonwebtoken`, which packages each failure mode into
/// its own [`ErrorKind`] variant; spiffe wraps the whole thing as
/// `InvalidToken(jwt_err)`. Without this drill-down every JWT-lib
/// failure would coalesce to "signature verification failed", which
/// is wrong for expired tokens, wrong-audience tokens, etc.
///
/// PII rule (spec §9.1) still applies — we use only the
/// `ErrorKind` discriminant, never the inner error's `Display`
/// (which can echo the failed claim's value).
fn map_jwt_token_error(kind: &ErrorKind) -> AttestorError {
    match kind {
        ErrorKind::ExpiredSignature => AttestorError::Rejected("credential expired".to_string()),
        ErrorKind::InvalidAudience => AttestorError::Rejected("audience mismatch".to_string()),
        ErrorKind::ImmatureSignature => AttestorError::Rejected("nbf in the future".to_string()),
        ErrorKind::InvalidIssuer => {
            // `iss` check; spiffe's validate does not configure this,
            // but if a future SDK version turns it on we want a
            // reasonable mapping.
            AttestorError::Rejected("issuer mismatch".to_string())
        }
        ErrorKind::InvalidSignature => {
            AttestorError::Rejected("signature verification failed".to_string())
        }
        // Catch-all: covers ErrorKind::Base64, Json, Utf8,
        // InvalidAlgorithmName, MissingRequiredClaim, and the
        // `#[non_exhaustive]` tail. None of these are clearly
        // "rejected" vs. "malformed"; spec §9 maps generic crypto-
        // lib failures to "signature verification failed" because
        // that's the load-bearing-but-uninformative answer.
        _ => AttestorError::Rejected("signature verification failed".to_string()),
    }
}

/// Discriminant-only tag for the forward-compat catch-all. Names the
/// variant without including its inner Display (which might leak the
/// credential's claims if a future variant carries decoded content).
fn other_variant_tag(_err: &JwtSvidError) -> &'static str {
    // Cannot use match { _ => "..." } meaningfully without committing
    // to a specific tag for each potential future variant. The Debug
    // impl of a non-exhaustive enum can include arbitrary content
    // depending on the variant's fields, which violates the PII rule.
    // Return a generic tag; the SDK upgrade is what would prompt us
    // to revisit this map.
    "non-exhaustive-fallback"
}

#[cfg(test)]
mod tests {
    use super::*;
    use spiffe::TrustDomain;

    #[test]
    fn malformed_variants_map_to_malformed() {
        assert!(matches!(
            map_spiffe_error(JwtSvidError::InvalidJwtFormat),
            AttestorError::Malformed(_)
        ));
        assert!(matches!(
            map_spiffe_error(JwtSvidError::InvalidBase64),
            AttestorError::Malformed(_)
        ));
        assert!(matches!(
            map_spiffe_error(JwtSvidError::MissingKeyId),
            AttestorError::Malformed(_)
        ));
        assert!(matches!(
            map_spiffe_error(JwtSvidError::InvalidTyp),
            AttestorError::Malformed(_)
        ));
        assert!(matches!(
            map_spiffe_error(JwtSvidError::UnsupportedAlgorithm),
            AttestorError::Malformed(_)
        ));
    }

    #[test]
    fn rejected_variants_map_to_rejected() {
        assert!(matches!(
            map_spiffe_error(JwtSvidError::InvalidExpiration),
            AttestorError::Rejected(_)
        ));
        assert!(matches!(
            map_spiffe_error(JwtSvidError::AuthorityNotFound("kid".to_string())),
            AttestorError::Rejected(_)
        ));
        let td = TrustDomain::try_from("example.org").unwrap();
        assert!(matches!(
            map_spiffe_error(JwtSvidError::BundleNotFound(td)),
            AttestorError::Rejected(_)
        ));
    }

    #[test]
    fn audience_mismatch_carries_spec_message_only() {
        // PII rule: the message MUST NOT include the audience values
        // from the rejected token nor the expected audience.
        let err = map_spiffe_error(JwtSvidError::InvalidAudience(
            vec!["got-aud-from-token".to_string()],
            vec!["expected-aud".to_string()],
        ));
        let msg = format!("{err}");
        assert!(msg.contains("audience mismatch"));
        assert!(!msg.contains("got-aud-from-token"));
        assert!(!msg.contains("expected-aud"));
    }

    #[test]
    fn jwt_verify_not_enabled_maps_to_internal() {
        assert!(matches!(
            map_spiffe_error(JwtSvidError::JwtVerifyNotEnabled),
            AttestorError::Internal(_)
        ));
    }
}
