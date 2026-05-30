//! Integration test for [`AzureKvSigner`] against a real Azure Key Vault
//! Managed HSM.
//!
//! Implements the [RFC 0017 §3.7 conformance pattern](../../../spec/rfcs/0017-external-signer-backends.md#37-conformance-pattern-for-non-seed-derivable-keys)
//! for non-seed-derivable keys: connect → public_key fetch → sign →
//! verify roundtrip, plus an adversarial wrong-message case.
//!
//! Skipped by default. Runs only when:
//! - `YUTHA_SIGNER_AZURE_KV_VAULT_URL` is set, AND
//! - `YUTHA_SIGNER_AZURE_KV_KEY_NAME` is set, AND
//! - `DefaultAzureCredential` can resolve a token (managed identity, or
//!   `AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_CLIENT_SECRET` env vars,
//!   or `az login` cached creds), AND
//! - the test is invoked with `cargo test -- --ignored`.
//!
//! See the crate README + the `docs/operator/azure-kv-signer.md`
//! walkthrough for the one-time `az keyvault` / `az hsm` provisioning
//! commands.

use yutha_crypto::verify;
use yutha_signer::Signer;
use yutha_signer_azure_kv::{AzureKvConfig, AzureKvSigner};

/// Returns `Some(AzureKvConfig)` if the operator has set the env vars,
/// otherwise `None`. The `DefaultAzureCredential` requirement is not
/// straightforwardly env-var-checkable, so we only gate on the vault
/// URL + key name and let `connect()` surface credential-chain
/// exhaustion as `SignerError::BackendUnavailable`.
fn skip_unless_env_set() -> Option<AzureKvConfig> {
    if std::env::var("YUTHA_SIGNER_AZURE_KV_VAULT_URL").is_err()
        || std::env::var("YUTHA_SIGNER_AZURE_KV_KEY_NAME").is_err()
    {
        eprintln!(
            "yutha-signer-azure-kv integration test skipped: \
             set YUTHA_SIGNER_AZURE_KV_VAULT_URL + YUTHA_SIGNER_AZURE_KV_KEY_NAME \
             (and ensure DefaultAzureCredential can resolve — `az login` or \
             managed identity) to run. See the crate README."
        );
        return None;
    }
    Some(
        AzureKvConfig::from_env()
            .expect("from_env succeeds when the env-var preconditions above are met"),
    )
}

/// The full RFC 0017 §3.7 conformance loop:
/// 1. `connect` succeeds against the operator-provisioned Managed HSM key
/// 2. `public_key` is well-formed Ed25519 (32 bytes)
/// 3. `sign_message` returns a 64-byte Ed25519 signature
/// 4. The signature `verify`s under the reported public key per RFC 8032
/// 5. Re-signing the same message produces the same byte-for-byte
///    signature (Ed25519 is deterministic).
#[tokio::test]
#[ignore = "requires Azure Managed HSM access — set YUTHA_SIGNER_AZURE_KV_* env vars + DefaultAzureCredential, then pass --ignored"]
async fn azure_kv_signer_full_conformance() {
    let Some(config) = skip_unless_env_set() else {
        return;
    };

    let signer = AzureKvSigner::connect(config)
        .await
        .expect("connect must succeed against operator-provisioned Managed HSM key");

    let pk = signer.public_key();
    assert_eq!(pk.value.len(), 32, "Ed25519 public key must be 32 bytes");

    let message = b"yutha-signer-azure-kv integration: connect + sign + verify";

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
#[ignore = "requires Azure Managed HSM access — set YUTHA_SIGNER_AZURE_KV_* env vars + DefaultAzureCredential, then pass --ignored"]
async fn azure_kv_signature_fails_for_different_message() {
    let Some(config) = skip_unless_env_set() else {
        return;
    };
    let signer = AzureKvSigner::connect(config).await.unwrap();
    let sig = signer.sign_message(b"message A").await.unwrap();
    assert!(
        verify(&signer.public_key(), b"message B", &sig).is_err(),
        "signature for A must not verify against B"
    );
}
