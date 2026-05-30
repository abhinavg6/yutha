//! Integration test for [`VaultSigner`] against a real HashiCorp Vault.
//!
//! Implements the [RFC 0017 §3.7 conformance pattern](../../../spec/rfcs/0017-external-signer-backends.md#37-conformance-pattern-for-non-seed-derivable-keys)
//! for non-seed-derivable keys: connect → public_key fetch → sign → verify
//! roundtrip, plus a few adversarial cases.
//!
//! Skipped by default. Runs only when:
//! - `YUTHA_SIGNER_VAULT_ADDR` is set, AND
//! - `YUTHA_SIGNER_VAULT_KEY` is set, AND
//! - an auth env var (`YUTHA_SIGNER_VAULT_TOKEN` or the AppRole pair) is set,
//! - the test is invoked with `cargo test -- --ignored`.
//!
//! See the crate README for the docker-vault one-liner that stands all of
//! this up.

use yutha_crypto::verify;
use yutha_signer::Signer;
use yutha_signer_vault::{VaultConfig, VaultSigner};

/// Returns `Some(VaultConfig)` if the operator has set the env vars,
/// otherwise `None`. We don't reach for `VaultConfig::from_env` here —
/// `from_env` is itself a fallible function and we want the absence of
/// env vars to mean "skip this test" rather than "fail with a missing-
/// env error."
fn skip_unless_env_set() -> Option<VaultConfig> {
    if std::env::var("YUTHA_SIGNER_VAULT_ADDR").is_err()
        || std::env::var("YUTHA_SIGNER_VAULT_KEY").is_err()
    {
        eprintln!(
            "yutha-signer-vault integration test skipped: \
             set YUTHA_SIGNER_VAULT_ADDR + YUTHA_SIGNER_VAULT_KEY + an auth env var \
             (see crate README) to run."
        );
        return None;
    }
    if std::env::var("YUTHA_SIGNER_VAULT_TOKEN").is_err()
        && (std::env::var("YUTHA_SIGNER_VAULT_APPROLE_ROLE_ID").is_err()
            || std::env::var("YUTHA_SIGNER_VAULT_APPROLE_SECRET_ID").is_err())
    {
        eprintln!(
            "yutha-signer-vault integration test skipped: \
             no auth env vars set (need YUTHA_SIGNER_VAULT_TOKEN or AppRole pair)."
        );
        return None;
    }
    Some(
        VaultConfig::from_env()
            .expect("from_env succeeds when the env-var preconditions above are met"),
    )
}

/// The full RFC 0017 §3.7 conformance loop:
/// 1. `connect` succeeds against the operator-provisioned key
/// 2. `public_key` is well-formed Ed25519
/// 3. `sign_message` returns a signature
/// 4. The signature `verify`s under the reported public key per RFC 8032
/// 5. Re-signing the same message produces the same byte-for-byte signature
///    (Ed25519 is deterministic; this is the same guarantee the Phase B
///    `concurrent_sign_safety` test asserts for `InProcessSigner`)
#[tokio::test]
#[ignore = "requires a real Vault — set YUTHA_SIGNER_VAULT_* env vars + pass --ignored"]
async fn vault_signer_full_conformance() {
    let Some(config) = skip_unless_env_set() else {
        return;
    };

    let signer = VaultSigner::connect(config)
        .await
        .expect("connect must succeed against operator-provisioned Vault");

    let pk = signer.public_key();
    assert_eq!(pk.value.len(), 32, "Ed25519 public key must be 32 bytes");

    let message = b"yutha-signer-vault integration: connect + sign + verify";

    let sig = signer
        .sign_message(message)
        .await
        .expect("sign must succeed against an authorised key");
    assert_eq!(sig.value.len(), 64, "Ed25519 signature must be 64 bytes");

    verify(&pk, message, &sig).expect("signature must verify under reported public key");

    // Determinism check.
    let sig2 = signer.sign_message(message).await.unwrap();
    assert_eq!(
        sig.value, sig2.value,
        "Ed25519 is deterministic; repeated sign over same message must match"
    );
}

/// Adversarial: signature for message A must NOT verify against message B.
/// The verify lib will return Err; we just need the assertion to hold so
/// we know the public key reported by `connect()` is actually the key Vault
/// signs with (not a stale cache, not a typo'd key path).
#[tokio::test]
#[ignore = "requires a real Vault — set YUTHA_SIGNER_VAULT_* env vars + pass --ignored"]
async fn vault_signature_fails_for_different_message() {
    let Some(config) = skip_unless_env_set() else {
        return;
    };
    let signer = VaultSigner::connect(config).await.unwrap();
    let sig = signer.sign_message(b"message A").await.unwrap();
    assert!(
        verify(&signer.public_key(), b"message B", &sig).is_err(),
        "signature for A must not verify against B"
    );
}
