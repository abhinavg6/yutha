//! Integration test for [`GcpKmsSigner`] against a real Google Cloud
//! KMS key version.
//!
//! Implements the [RFC 0017 §3.7 conformance pattern](../../../spec/rfcs/0017-external-signer-backends.md#37-conformance-pattern-for-non-seed-derivable-keys)
//! for non-seed-derivable keys: connect → public_key fetch → sign →
//! verify roundtrip, plus an adversarial wrong-message case.
//!
//! Skipped by default. Runs only when:
//! - `YUTHA_SIGNER_GCP_KMS_KEY_VERSION` is set, AND
//! - ADC is configured (`GOOGLE_APPLICATION_CREDENTIALS` env var or
//!   `gcloud auth application-default login` already run), AND
//! - the test is invoked with `cargo test -- --ignored`.
//!
//! See the crate README + the docs/operator/gcp-kms-signer.md
//! walkthrough for the one-time `gcloud kms` provisioning commands.

use yutha_crypto::verify;
use yutha_signer::Signer;
use yutha_signer_gcp_kms::{GcpKmsConfig, GcpKmsSigner};

/// Returns `Some(GcpKmsConfig)` if the operator has set the env vars,
/// otherwise `None`. The ADC requirement is not env-var-checkable
/// (gcloud-cli leaves a JSON file in `~/.config/gcloud/`), so we only
/// gate on the key-version env var and let `connect()` surface ADC
/// failures as `SignerError::BackendRejected`.
fn skip_unless_env_set() -> Option<GcpKmsConfig> {
    if std::env::var("YUTHA_SIGNER_GCP_KMS_KEY_VERSION").is_err() {
        eprintln!(
            "yutha-signer-gcp-kms integration test skipped: \
             set YUTHA_SIGNER_GCP_KMS_KEY_VERSION (and run `gcloud auth \
             application-default login` or set GOOGLE_APPLICATION_CREDENTIALS) \
             to run. See the crate README."
        );
        return None;
    }
    Some(
        GcpKmsConfig::from_env()
            .expect("from_env succeeds when the env-var precondition above is met"),
    )
}

/// The full RFC 0017 §3.7 conformance loop:
/// 1. `connect` succeeds against the operator-provisioned key version
/// 2. `public_key` is well-formed Ed25519
/// 3. `sign_message` returns a signature
/// 4. The signature `verify`s under the reported public key per RFC 8032
/// 5. Re-signing the same message produces the same byte-for-byte
///    signature (Ed25519 is deterministic — same property the Phase B
///    `concurrent_sign_safety` test asserts for `InProcessSigner`).
#[tokio::test]
#[ignore = "requires GCP KMS access — set YUTHA_SIGNER_GCP_KMS_KEY_VERSION + ADC, then pass --ignored"]
async fn gcp_kms_signer_full_conformance() {
    let Some(config) = skip_unless_env_set() else {
        return;
    };

    let signer = GcpKmsSigner::connect(config)
        .await
        .expect("connect must succeed against operator-provisioned KMS key");

    let pk = signer.public_key();
    assert_eq!(pk.value.len(), 32, "Ed25519 public key must be 32 bytes");

    let message = b"yutha-signer-gcp-kms integration: connect + sign + verify";

    let sig = signer
        .sign_message(message)
        .await
        .expect("sign must succeed against an authorised key");
    assert_eq!(sig.value.len(), 64, "Ed25519 signature must be 64 bytes");

    verify(&pk, message, &sig).expect("signature must verify under reported public key");

    let sig2 = signer.sign_message(message).await.unwrap();
    assert_eq!(
        sig.value, sig2.value,
        "Ed25519 is deterministic; repeated sign over same message must match"
    );
}

/// Adversarial: signature for message A must NOT verify against message B.
#[tokio::test]
#[ignore = "requires GCP KMS access — set YUTHA_SIGNER_GCP_KMS_KEY_VERSION + ADC, then pass --ignored"]
async fn gcp_kms_signature_fails_for_different_message() {
    let Some(config) = skip_unless_env_set() else {
        return;
    };
    let signer = GcpKmsSigner::connect(config).await.unwrap();
    let sig = signer.sign_message(b"message A").await.unwrap();
    assert!(
        verify(&signer.public_key(), b"message B", &sig).is_err(),
        "signature for A must not verify against B"
    );
}
