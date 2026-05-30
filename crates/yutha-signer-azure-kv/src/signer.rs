//! [`AzureKvSigner`] — `Signer` impl backed by Azure Key Vault Managed HSM.
//!
//! Implements [RFC 0017 §4.3](../../../../spec/rfcs/0017-external-signer-backends.md#43-azure-key-vault-managed-hsm-yutha-signer-azure-kv).
//!
//! Construction (`connect()`) does three things, in order:
//!
//! 1. Build a [`KeyClient`] using
//!    [`azure_identity::DeveloperToolsCredential`] (covers az CLI +
//!    developer-environment paths). Production deployments using
//!    Managed Identity or Workload Identity should call
//!    [`AzureKvSigner::connect_with_credential`] instead.
//! 2. `get_key(name, options{ key_version, .. })` to fetch the JWK and
//!    assert `kty=OKP` (or `OKP-HSM`) + `crv=Ed25519`. Anything else
//!    fails at connect-time with [`SignerError::UnsupportedAlgorithm`].
//! 3. Read the JWK `x` field as 32 raw Ed25519 bytes (the SDK
//!    base64url-decodes for us) and cache them. After this point
//!    [`Signer::public_key`] is sync.
//!
//! [`Signer::sign_message`] then becomes a single `keys/<name>/sign`
//! HTTPS call per signing event. For EdDSA the request body's `value`
//! field is the raw data to sign (Azure's "digest" API naming is
//! generic — EdDSA does not pre-hash).
//!
//! # Why `UnknownValue(...)` strings?
//!
//! The `azure_security_keyvault_keys` v0.14 generated enums
//! (`KeyType`, `CurveName`, `SignatureAlgorithm`) don't yet have
//! first-class variants for `OKP-HSM` / `Ed25519` / `EdDSA` — those
//! were added to the Microsoft Python/dotnet SDKs but haven't landed
//! in the Rust generated code as of 2026-05. We use the
//! `UnknownValue(String)` escape hatch on every enum: the wire
//! format is unaffected (these strings round-trip through the
//! enum's `FromStr`/`AsRef<str>` impls), and we can switch to the
//! named variants in a one-line follow-on when Microsoft regenerates.

use crate::config::AzureKvConfig;
use crate::error::map_azure_error;
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_keys::clients::KeyClient;
use azure_security_keyvault_keys::models::{
    CurveName, KeyClientGetKeyOptions, KeyClientSignOptions, KeyType, SignParameters,
    SignatureAlgorithm,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use yutha_core::{PublicKey, Signature, SignatureAlgorithm as YuthaSignatureAlgorithm};
use yutha_signer::{Signer, SignerError};

/// Azure JWK wire string for the EdDSA-on-Curve25519 signing algorithm.
const ALG_EDDSA: &str = "EdDSA";
/// Azure JWK wire string for the Ed25519 curve.
const CRV_ED25519: &str = "Ed25519";
/// Azure JWK wire strings for the OKP key type. `OKP-HSM` is the
/// Managed HSM tier's HSM-backed variant; `OKP` covers software-backed
/// keys (which standard Key Vault does not actually support for
/// Ed25519, but the SDK won't refuse to return one).
const KTY_OKP: &str = "OKP";
const KTY_OKP_HSM: &str = "OKP-HSM";

/// `Signer` implementation that delegates Ed25519 signing to an Azure
/// Key Vault Managed HSM key. The private key never leaves the HSM
/// partition.
///
/// See the crate-level docs for the overall posture; see
/// [`AzureKvSigner::connect`] for the construction flow.
pub struct AzureKvSigner {
    client: Arc<KeyClient>,
    key_name: String,
    /// Pinned key version, or empty string for "latest" (Azure SDK
    /// convention — empty `key_version` selects the current version).
    key_version: String,
    public_key: PublicKey,
    /// SHA-256 of `public_key.value`, precomputed at connect so
    /// `sign_message` doesn't re-hash on every call.
    key_fingerprint: Vec<u8>,
}

impl std::fmt::Debug for AzureKvSigner {
    /// Hand-rolled so the inner client (which holds the auth token
    /// in its internal stack) isn't fully rendered. Public key is
    /// small + non-secret, fine to print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKvSigner")
            .field("key_name", &self.key_name)
            .field("key_version", &self.key_version)
            .field("public_key", &self.public_key)
            .field(
                "client",
                &"<azure_security_keyvault_keys::KeyClient redacted>",
            )
            .finish()
    }
}

impl AzureKvSigner {
    /// Connect using [`DeveloperToolsCredential`] — covers `az login`,
    /// VS Code, IntelliJ, and the rest of the developer-tooling
    /// auth chain. Appropriate for local development and CI runs.
    ///
    /// Production deployments using Managed Identity, Workload
    /// Identity, or a long-lived service principal should use
    /// [`AzureKvSigner::connect_with_credential`] and supply an
    /// explicit credential.
    pub async fn connect(config: AzureKvConfig) -> Result<Self, SignerError> {
        let credential = DeveloperToolsCredential::new(None).map_err(|e| {
            SignerError::Internal(format!("DeveloperToolsCredential build failed: {e}"))
        })?;
        Self::connect_with_credential(config, credential).await
    }

    /// Connect with an explicit `TokenCredential` — the right entry
    /// point for production. Operators pass any
    /// [`azure_identity`](https://docs.rs/azure_identity) credential
    /// (e.g. `ManagedIdentityCredential::new(...)` on AKS / Container
    /// Apps; `WorkloadIdentityCredential::new(...)` on GKE-style
    /// federated identities; `ClientSecretCredential::new(...)` for
    /// service-principal env-var setups).
    ///
    /// # Errors
    ///
    /// - [`SignerError::Internal`] for client construction failures.
    /// - [`SignerError::BackendRejected`] for 401/403/404/400 from Azure.
    /// - [`SignerError::BackendUnavailable`] for transport or 5xx.
    /// - [`SignerError::UnsupportedAlgorithm`] if the key isn't OKP/Ed25519.
    pub async fn connect_with_credential(
        config: AzureKvConfig,
        credential: Arc<dyn TokenCredential>,
    ) -> Result<Self, SignerError> {
        if !config.looks_like_managed_hsm() {
            tracing::warn!(
                vault_url = %config.vault_url,
                "yutha-signer-azure-kv: vault URL does not look like a Managed HSM \
                 (https://*.managedhsm.azure.net). Standard Key Vault does NOT support \
                 Ed25519; expect SignerError::UnsupportedAlgorithm if this is a standard \
                 Key Vault. See RFC 0017 §4.3."
            );
        }

        let client = KeyClient::new(&config.vault_url, credential, None)
            .map_err(|e| SignerError::Internal(format!("KeyClient build failed: {e}")))?;

        // Azure SDK takes the version in the options struct. The "latest"
        // path is signalled by an empty string, not `None`.
        let key_version_for_call = config.key_version.clone().unwrap_or_default();

        // get_key returns Response<Key>; `.into_body()` returns the
        // raw streaming body, but `.into_model()` is the sync typed
        // deserialiser the SDK README documents. It returns
        // Result<T, azure_core::Error>, so map_azure_error works on
        // the deserialise failure path.
        let key_bundle = client
            .get_key(
                &config.key_name,
                Some(KeyClientGetKeyOptions {
                    key_version: Some(key_version_for_call.clone()),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| map_azure_error(e, "GetKey"))?
            .into_model()
            .map_err(|e| map_azure_error(e, "GetKey deserialise"))?;

        let jwk = key_bundle.key.ok_or_else(|| {
            SignerError::Internal(format!(
                "Azure get_key for '{}' returned no JWK body",
                config.key_name
            ))
        })?;

        // The v0.14 SDK doesn't have first-class Okp/Ed25519 enum
        // variants yet — Azure returns them as the UnknownValue
        // escape-hatch string. Accept either OKP or OKP-HSM (the
        // HSM-backed flavour Managed HSM uses).
        let kty_ok = matches!(
            jwk.kty.as_ref(),
            Some(KeyType::UnknownValue(s)) if s == KTY_OKP || s == KTY_OKP_HSM
        );
        let crv_ok = matches!(
            jwk.crv.as_ref(),
            Some(CurveName::UnknownValue(s)) if s == CRV_ED25519
        );
        if !(kty_ok && crv_ok) {
            return Err(SignerError::UnsupportedAlgorithm(format!(
                "Azure key '{}' has kty={:?} crv={:?}; expected (OKP|OKP-HSM, Ed25519). \
                 If this is a standard Key Vault, recreate the key in a Managed HSM \
                 (`.managedhsm.azure.net`) — standard Key Vault does not support \
                 Ed25519. See RFC 0015 §3.1 invariant 2.",
                config.key_name, jwk.kty, jwk.crv
            )));
        }

        // The Azure SDK deserialises JWK `x` as Vec<u8> (raw bytes,
        // already base64url-decoded). For Ed25519 the public key is
        // exactly 32 bytes.
        let pk_bytes = jwk.x.ok_or_else(|| {
            SignerError::UnsupportedAlgorithm(format!(
                "Azure key '{}' returned no `x` field on the JWK",
                config.key_name
            ))
        })?;
        if pk_bytes.len() != 32 {
            return Err(SignerError::UnsupportedAlgorithm(format!(
                "Azure key '{}' returned a `x` field of {} bytes; Ed25519 public key \
                 must be 32 bytes",
                config.key_name,
                pk_bytes.len()
            )));
        }

        let public_key =
            PublicKey::new(YuthaSignatureAlgorithm::Ed25519, pk_bytes).map_err(|e| {
                SignerError::Internal(format!("invalid public-key bytes from Azure: {e}"))
            })?;
        let key_fingerprint = Sha256::digest(&public_key.value).to_vec();

        tracing::info!(
            vault_url = %config.vault_url,
            key_name = %config.key_name,
            key_version = %if key_version_for_call.is_empty() { "<latest>" } else { &key_version_for_call },
            "yutha-signer-azure-kv connected"
        );

        Ok(Self {
            client: Arc::new(client),
            key_name: config.key_name,
            key_version: key_version_for_call,
            public_key,
            key_fingerprint,
        })
    }
}

#[async_trait]
impl Signer for AzureKvSigner {
    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // For EdDSA the `value` field is the RAW message — Azure's
        // "digest" API naming is generic, but EdDSA does not pre-hash.
        // Limit per Azure docs is 64KB; Yutha's largest signed
        // artefacts are well under that.
        //
        // EdDSA is the UnknownValue escape hatch in v0.14 (see crate
        // docs).
        let sign_params = SignParameters {
            algorithm: Some(SignatureAlgorithm::UnknownValue(ALG_EDDSA.to_string())),
            value: Some(message.to_vec()),
        };

        let request_body = sign_params
            .try_into()
            .map_err(|e| SignerError::Internal(format!("SignParameters → body: {e}")))?;

        let sign_result = self
            .client
            .sign(
                &self.key_name,
                request_body,
                Some(KeyClientSignOptions {
                    key_version: Some(self.key_version.clone()),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| map_azure_error(e, "Sign"))?
            .into_model()
            .map_err(|e| map_azure_error(e, "Sign deserialise"))?;

        let sig_bytes = sign_result
            .result
            .ok_or_else(|| SignerError::Internal("Azure sign returned no `result` bytes".into()))?;

        Signature::new(
            YuthaSignatureAlgorithm::Ed25519,
            sig_bytes,
            self.key_fingerprint.clone(),
        )
        .map_err(|e| {
            SignerError::Internal(format!(
                "Azure returned signature bytes that did not pass length check: {e}"
            ))
        })
    }
}
