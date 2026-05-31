//! Manual JWT payload decode for the claims `spiffe::JwtSvid` does
//! not surface.
//!
//! [`spiffe::JwtSvid::parse_and_validate`] covers signature, `sub`,
//! `aud`, `exp`, `kid`, `alg`, and `typ`. It does NOT surface:
//!
//!   - `nbf` / `iat` claims — needed for the
//!     [`attestor-spiffe.md` §3 step 7e–7f](../../../spec/identity-keys/attestor-spiffe.md#3-verification-algorithm)
//!     clock-skew-tolerant freshness checks;
//!   - the `selectors` custom claim — needed for the spec §8
//!     attribute projection.
//!
//! This module extracts only those fields, after the SDK has already
//! verified the signature. The payload bytes we decode here are
//! therefore *already trusted*; we are not re-validating, just
//! reading.
//!
//! # Why not use `JwtSvid::claims()`?
//!
//! The SDK's `Claims` type exposes the standard JWT claims as typed
//! fields but does not provide an escape hatch for custom claims
//! like `selectors`. Decoding the middle segment manually is
//! straightforward, well-documented, and lets us apply the spec's
//! caps before the data hits the receipt evidence.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use std::collections::BTreeMap;
use yutha_attestor::AttestorError;

/// Subset of payload claims this Attestor extracts manually, beyond
/// what `JwtSvid` surfaces.
#[derive(Debug, Default)]
pub(crate) struct ExtraClaims {
    /// `iat` claim (Unix seconds) if present + numeric. `None` if
    /// the claim is absent, non-numeric, or out of `i64` range.
    pub(crate) iat: Option<i64>,
    /// `nbf` claim (Unix seconds) if present + numeric. Same shape
    /// as `iat`.
    pub(crate) nbf: Option<i64>,
    /// `selectors` claim projected to `string → string`. `None` if
    /// the claim is absent OR if any value is non-string (the spec's
    /// "skip the whole claim" rule from §8.1).
    pub(crate) selectors: Option<BTreeMap<String, String>>,
}

/// Extract [`ExtraClaims`] from an already-signature-verified JWT.
///
/// # Errors
///
/// - [`AttestorError::Malformed`] if the token does not have at least
///   3 dot-separated parts, or if the payload segment fails to
///   base64url-decode, or if the decoded bytes are not JSON. These
///   are unreachable in practice because the SDK's parse_and_validate
///   already passed — but defence-in-depth: if it somehow drifts, we
///   return the same `Malformed` shape the rest of the verify path
///   uses.
///
/// PII rule (`attestor-spiffe.md` §9.1): error messages MUST NOT
/// include the payload contents.
pub(crate) fn decode_extra_claims(token: &str) -> Result<ExtraClaims, AttestorError> {
    let payload_segment = token.split('.').nth(1).ok_or_else(|| {
        AttestorError::Malformed("token does not contain a payload segment".to_string())
    })?;

    let bytes = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(|_| AttestorError::Malformed("JWT payload base64url decode failed".to_string()))?;

    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        // Don't include the inner serde_json error — it can echo the
        // payload's near-the-error bytes. The spec's §9 PII rule
        // applies.
        AttestorError::Malformed("payload not JSON".to_string())
    })?;

    let map = match value {
        Value::Object(m) => m,
        _ => {
            return Err(AttestorError::Malformed(
                "payload is JSON but not an object".to_string(),
            ));
        }
    };

    let iat = map.get("iat").and_then(value_as_unix_seconds);
    let nbf = map.get("nbf").and_then(value_as_unix_seconds);
    let selectors = map.get("selectors").and_then(extract_string_map);

    Ok(ExtraClaims {
        iat,
        nbf,
        selectors,
    })
}

/// Parse a JSON value as Unix-epoch seconds. Accepts JSON numbers
/// (integer or floating; the fractional part is truncated). Returns
/// `None` for any other type — we do NOT fail validation just
/// because a claim is the wrong shape; per spec §3 step 7, missing
/// `iat`/`nbf` is fine, so wrong-shaped is treated the same.
fn value_as_unix_seconds(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

/// Extract `selectors` per spec §8.1: object whose values are all
/// strings, projected to `BTreeMap<String, String>`. Returns `None`
/// if any value is non-string (the whole claim is skipped, not
/// partial). Caller logs the skip; we just signal it via `None`.
fn extract_string_map(v: &Value) -> Option<BTreeMap<String, String>> {
    let obj = v.as_object()?;
    let mut out = BTreeMap::new();
    for (k, val) in obj {
        let s = val.as_str()?;
        out.insert(k.clone(), s.to_string());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode an object as a JWT-shaped token (header.payload.sig).
    /// The header + signature segments are dummies — `decode_extra_claims`
    /// only reads the payload.
    fn token_with_payload(payload: &Value) -> String {
        let dummy_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"k1"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let dummy_sig = URL_SAFE_NO_PAD.encode(b"dummy-signature");
        format!("{dummy_header}.{payload_b64}.{dummy_sig}")
    }

    #[test]
    fn empty_payload_returns_all_none() {
        let token = token_with_payload(&serde_json::json!({
            "sub": "spiffe://example.org/foo",
            "aud": ["yutha-test"],
            "exp": 9_999_999_999_i64,
        }));
        let claims = decode_extra_claims(&token).unwrap();
        assert!(claims.iat.is_none());
        assert!(claims.nbf.is_none());
        assert!(claims.selectors.is_none());
    }

    #[test]
    fn iat_and_nbf_extracted_as_integers() {
        let token = token_with_payload(&serde_json::json!({
            "iat": 1_768_000_000_i64,
            "nbf": 1_768_000_005_i64,
            "exp": 9_999_999_999_i64,
        }));
        let claims = decode_extra_claims(&token).unwrap();
        assert_eq!(claims.iat, Some(1_768_000_000));
        assert_eq!(claims.nbf, Some(1_768_000_005));
    }

    #[test]
    fn iat_extracted_from_floating_point_with_truncation() {
        let token = token_with_payload(&serde_json::json!({
            "iat": 1_768_000_000.999_f64,
        }));
        let claims = decode_extra_claims(&token).unwrap();
        assert_eq!(claims.iat, Some(1_768_000_000));
    }

    #[test]
    fn nbf_non_numeric_is_silently_ignored() {
        let token = token_with_payload(&serde_json::json!({
            "nbf": "not-a-number",
        }));
        let claims = decode_extra_claims(&token).unwrap();
        // Spec §3 step 7: missing-or-wrong-shape `nbf` is fine.
        // (The freshness check is only enforced when the claim is
        // present and numeric.)
        assert!(claims.nbf.is_none());
    }

    #[test]
    fn selectors_string_map_round_trips() {
        let token = token_with_payload(&serde_json::json!({
            "selectors": {
                "k8s_ns": "billing",
                "k8s_sa": "processor",
            }
        }));
        let claims = decode_extra_claims(&token).unwrap();
        let selectors = claims.selectors.expect("string-map selectors");
        assert_eq!(selectors.get("k8s_ns").map(|s| s.as_str()), Some("billing"));
        assert_eq!(
            selectors.get("k8s_sa").map(|s| s.as_str()),
            Some("processor")
        );
    }

    #[test]
    fn selectors_with_non_string_value_is_skipped_entirely() {
        // Spec §8.1: "If any value in `selectors` is not a string …
        // the Attestor MUST log a warning and skip the entire claim".
        let token = token_with_payload(&serde_json::json!({
            "selectors": {
                "k8s_ns": "billing",
                "unix_uid": 1000,
            }
        }));
        let claims = decode_extra_claims(&token).unwrap();
        assert!(
            claims.selectors.is_none(),
            "mixed-type selectors must skip the whole claim"
        );
    }

    #[test]
    fn selectors_with_array_value_is_skipped_entirely() {
        let token = token_with_payload(&serde_json::json!({
            "selectors": {
                "labels": ["a", "b"],
            }
        }));
        let claims = decode_extra_claims(&token).unwrap();
        assert!(claims.selectors.is_none());
    }

    #[test]
    fn selectors_non_object_is_treated_as_absent() {
        let token = token_with_payload(&serde_json::json!({
            "selectors": "not-an-object",
        }));
        let claims = decode_extra_claims(&token).unwrap();
        assert!(claims.selectors.is_none());
    }

    // --- Defence-in-depth: malformed inputs (unreachable in
    // practice because the SDK validated first, but the function
    // must not panic) ---

    #[test]
    fn malformed_no_payload_segment() {
        let err = decode_extra_claims("just-one-segment").expect_err("err");
        assert!(matches!(err, AttestorError::Malformed(_)));
    }

    #[test]
    fn malformed_payload_not_base64() {
        let token = "header.@@@not-b64@@@.signature";
        let err = decode_extra_claims(token).expect_err("err");
        assert!(matches!(err, AttestorError::Malformed(_)));
    }

    #[test]
    fn malformed_payload_not_json() {
        let dummy_header = URL_SAFE_NO_PAD.encode(br#"{}"#);
        let payload = URL_SAFE_NO_PAD.encode(b"not json");
        let dummy_sig = URL_SAFE_NO_PAD.encode(b"sig");
        let token = format!("{dummy_header}.{payload}.{dummy_sig}");
        let err = decode_extra_claims(&token).expect_err("err");
        match err {
            AttestorError::Malformed(msg) => {
                assert!(msg.contains("payload not JSON"))
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn pii_rule_no_payload_content_in_error() {
        // Construct a payload with a secret-looking claim and verify
        // the error message doesn't echo it.
        let dummy_header = URL_SAFE_NO_PAD.encode(br#"{}"#);
        let payload = URL_SAFE_NO_PAD.encode(b"sub=SUPER-SECRET-IDENTITY-PII");
        let dummy_sig = URL_SAFE_NO_PAD.encode(b"sig");
        let token = format!("{dummy_header}.{payload}.{dummy_sig}");
        let err = decode_extra_claims(&token).expect_err("err");
        let msg = format!("{err}");
        assert!(
            !msg.contains("SUPER-SECRET-IDENTITY-PII"),
            "PII leak in error: {msg}"
        );
    }
}
