//! F7 — forged ID-token coverage of the
//! [`OidcAttestor`](yutha_attestor_oidc::OidcAttestor) verify path
//! that requires a valid signature (i.e., tests that go *past* step 5
//! of the spec §3 algorithm).
//!
//! Each test in this file:
//!   1. Builds a [`SigningFixture`](common::SigningFixture) — keypair
//!      plus matching one-key JWKS.
//!   2. Materialises the JWKS as a temp file.
//!   3. Constructs the [`OidcAttestor`](yutha_attestor_oidc::OidcAttestor)
//!      pointing at the temp JWKS (static-file source — no HTTP).
//!   4. Mints a JWT with the desired claim shape.
//!   5. Calls `verify` and asserts the expected outcome.
//!
//! Negative-path tests that DON'T require a valid signature (empty
//! credential, malformed JWS, missing kid, unsupported typ/alg, kid
//! not in JWKS, junk-signature) live in the in-crate unit tests of
//! `src/attestor.rs::tests` — they don't need a real keypair and so
//! don't pay the keygen cost.
//!
//! Spec: /spec/identity-keys/attestor-oidc.md §3 (verify algorithm),
//! §7 (external_identity shape), §8 (claim projection), §9 (error
//! mapping).

mod common;

use common::{
    config_with_static_file, dummy_context, happy_claims, now_secs, EXPECTED_AUDIENCE,
    EXPECTED_ISSUER,
};
use serde_json::Value;
use yutha_attestor::{Attestor, AttestorError};
use yutha_attestor_oidc::OidcAttestor;

// =====================================================================
// Happy-path round-trips: prove the full 9-step algorithm works for
// each algorithm we support.
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_rs256_roundtrips() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .expect("connect against static JWKS");

    let token = fx.mint_token(&happy_claims("user-123"));
    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("happy-path RS256 verify");

    assert_eq!(
        identity.external_identity,
        format!("oidc:{EXPECTED_ISSUER}:user-123"),
    );
    assert!(identity.credential_expires_at.is_some());
    assert!(identity.attributes.is_empty(), "no projection allowlisted");
}

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_eddsa_roundtrips() {
    let fx = common::SigningFixture::new_eddsa();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .expect("connect against EdDSA JWKS");

    let token = fx.mint_token(&happy_claims("ed-user"));
    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("happy-path EdDSA verify");

    assert_eq!(
        identity.external_identity,
        format!("oidc:{EXPECTED_ISSUER}:ed-user"),
    );
    assert!(identity.credential_expires_at.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_es256_roundtrips() {
    let fx = common::SigningFixture::new_es256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .expect("connect against ES256 JWKS");

    let token = fx.mint_token(&happy_claims("ec-user"));
    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("happy-path ES256 verify");

    assert_eq!(
        identity.external_identity,
        format!("oidc:{EXPECTED_ISSUER}:ec-user"),
    );
}

// =====================================================================
// Claim-failure rows: signature is valid but claim values are wrong.
// These are the spec §9 rows that the F4 negative-path tests in
// src/attestor.rs couldn't reach without a real signing key.
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn wrong_issuer_rejected_with_issuer_mismatch() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .unwrap();

    let mut claims = happy_claims("u");
    claims.as_object_mut().unwrap().insert(
        "iss".into(),
        Value::String("https://attacker.example.com".into()),
    );

    let token = fx.mint_token(&claims);
    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .unwrap_err();

    match err {
        AttestorError::Rejected(msg) => {
            assert_eq!(msg, "issuer mismatch");
        }
        other => panic!("expected Rejected(issuer mismatch); got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_audience_rejected_with_audience_mismatch() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .unwrap();

    let mut claims = happy_claims("u");
    claims
        .as_object_mut()
        .unwrap()
        .insert("aud".into(), Value::String("not-yutha".into()));

    let token = fx.mint_token(&claims);
    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .unwrap_err();

    match err {
        AttestorError::Rejected(msg) => {
            assert_eq!(msg, "audience mismatch");
        }
        other => panic!("expected Rejected(audience mismatch); got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_credential_rejected() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .unwrap();

    let mut claims = happy_claims("u");
    // Hardcoded past timestamp (year 2001) to avoid skew-tolerance
    // ambiguity. Per the time-relative-fixtures memory entry.
    claims
        .as_object_mut()
        .unwrap()
        .insert("exp".into(), Value::Number(1_000_000_000.into()));

    let token = fx.mint_token(&claims);
    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .unwrap_err();

    match err {
        AttestorError::Rejected(msg) => {
            assert_eq!(msg, "credential expired");
        }
        other => panic!("expected Rejected(credential expired); got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn iat_in_future_rejected() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .unwrap();

    let mut claims = happy_claims("u");
    // iat well past now + 60s clock skew tolerance.
    claims
        .as_object_mut()
        .unwrap()
        .insert("iat".into(), Value::Number((now_secs() + 3600).into()));

    let token = fx.mint_token(&claims);
    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .unwrap_err();

    match err {
        AttestorError::Rejected(msg) => {
            assert_eq!(msg, "iat in the future");
        }
        other => panic!("expected Rejected(iat in the future); got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nbf_in_future_rejected() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .unwrap();

    let mut claims = happy_claims("u");
    claims
        .as_object_mut()
        .unwrap()
        .insert("nbf".into(), Value::Number((now_secs() + 3600).into()));

    let token = fx.mint_token(&claims);
    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .unwrap_err();

    match err {
        AttestorError::Rejected(msg) => {
            assert_eq!(msg, "nbf in the future");
        }
        other => panic!("expected Rejected(nbf in the future); got {other:?}"),
    }
}

// =====================================================================
// Claim projection (spec §8): operator-allowlisted claims land in
// AttestedIdentity.attributes; non-allowlisted ones don't.
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn allowlisted_claims_project_into_attributes() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let mut config = config_with_static_file(jwks_file.path());
    config.project_claims = vec!["groups".into(), "email".into()];
    let attestor = OidcAttestor::connect(config).await.unwrap();

    let mut claims = happy_claims("alice");
    let obj = claims.as_object_mut().unwrap();
    obj.insert(
        "groups".into(),
        Value::Array(vec![
            Value::String("admin".into()),
            Value::String("auditor".into()),
        ]),
    );
    obj.insert("email".into(), Value::String("alice@example.com".into()));
    // Add a claim that's NOT allowlisted — MUST NOT project.
    obj.insert("department".into(), Value::String("platform".into()));

    let token = fx.mint_token(&claims);
    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("verify with projection");

    assert_eq!(
        identity.attributes.get("groups").map(String::as_str),
        Some("admin,auditor"),
    );
    assert_eq!(
        identity.attributes.get("email").map(String::as_str),
        Some("alice@example.com"),
    );
    assert!(
        !identity.attributes.contains_key("department"),
        "non-allowlisted claim leaked into attributes: {:?}",
        identity.attributes,
    );
}

// =====================================================================
// external_identity composition (spec §7): always `oidc:<iss>:<sub>`.
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn external_identity_carries_oidc_prefix_and_full_issuer() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .unwrap();

    let token = fx.mint_token(&happy_claims("subj-with-special:colons"));
    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .unwrap();

    // The full iss URL is preserved verbatim — auditors substring-
    // match on `oidc:<iss>:` to filter by issuer.
    assert!(
        identity
            .external_identity
            .starts_with(&format!("oidc:{EXPECTED_ISSUER}:")),
        "got: {}",
        identity.external_identity,
    );
    // sub is appended verbatim, no normalisation.
    assert!(
        identity
            .external_identity
            .ends_with(":subj-with-special:colons"),
        "got: {}",
        identity.external_identity,
    );
}

// =====================================================================
// Audience-as-array per spec §2.2 ("aud | string OR array-of-string").
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn aud_array_containing_expected_audience_accepted() {
    let fx = common::SigningFixture::new_rs256();
    let jwks_file = fx.to_temp_jwks();
    let attestor = OidcAttestor::connect(config_with_static_file(jwks_file.path()))
        .await
        .unwrap();

    let mut claims = happy_claims("u");
    claims.as_object_mut().unwrap().insert(
        "aud".into(),
        Value::Array(vec![
            Value::String("some-other-rp".into()),
            Value::String(EXPECTED_AUDIENCE.into()),
            Value::String("another-rp".into()),
        ]),
    );

    let token = fx.mint_token(&claims);
    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("aud array containing expected_audience must be accepted");

    assert!(identity.external_identity.starts_with("oidc:"));
}
