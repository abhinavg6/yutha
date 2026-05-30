//! Azure Key Vault Managed HSM backend for the Yutha [`Signer`] trait.
//!
//! Implements [RFC 0017 §4.3 — External Signer backends: Azure Key Vault](../../../spec/rfcs/0017-external-signer-backends.md#43-azure-key-vault-managed-hsm-yutha-signer-azure-kv).
//! The signing key lives inside an Azure Managed HSM (FIPS 140-2 Level
//! 3); every [`Signer::sign_message`] call is an HTTPS RPC to
//! `keys/<name>/sign` with `alg=EdDSA`. The substrate never sees the
//! private bytes — they cannot leave the HSM partition.
//!
//! # Tier requirement (**important**)
//!
//! Ed25519 / EdDSA is only available on **Azure Key Vault Managed HSM**
//! (`*.managedhsm.azure.net`). The standard Key Vault tier
//! (`*.vault.azure.net`) does NOT support Ed25519. If you point this
//! crate at a standard Key Vault, [`AzureKvSigner::connect`] will
//! either:
//!
//! - succeed at `get_key` but observe a non-Ed25519 algorithm and
//!   return [`SignerError::UnsupportedAlgorithm`], or
//! - fail the first `sign` call with `BadRequest`-mapped
//!   [`SignerError::BackendRejected`].
//!
//! The crate emits a `tracing::warn!` at connect time if the vault URL
//! doesn't end in `.managedhsm.azure.net` so misconfiguration shows up
//! in operator logs before the first signing event.
//!
//! # Quick orientation
//!
//! ```no_run
//! use yutha_signer::Signer;
//! use yutha_signer_azure_kv::{AzureKvConfig, AzureKvSigner};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = AzureKvSigner::connect(AzureKvConfig {
//!     vault_url: "https://yutha-hsm.managedhsm.azure.net".into(),
//!     key_name: "bootstrap".into(),
//!     key_version: Some("a1b2c3d4e5f6...".into()), // pin a specific version
//! })
//! .await?;
//!
//! let pk = signer.public_key();
//! let sig = signer.sign_message(b"hello azure").await?;
//! # Ok(()) }
//! ```
//!
//! # Operator surface (env-var convention)
//!
//! Per RFC 0017 §3.2, the env-var prefix for this backend is
//! `YUTHA_SIGNER_AZURE_KV_*`. [`AzureKvConfig::from_env`] populates
//! the config from:
//!
//! - `YUTHA_SIGNER_AZURE_KV_VAULT_URL` — full Managed HSM URL, e.g.
//!   `https://yutha-hsm.managedhsm.azure.net` (required).
//! - `YUTHA_SIGNER_AZURE_KV_KEY_NAME` — name of the Ed25519 key
//!   (required).
//! - `YUTHA_SIGNER_AZURE_KV_KEY_VERSION` — explicit key-version hex
//!   string. Optional; absent means "use the latest" (which has the
//!   staleness caveats called out in RFC 0017 §3.6 — pin explicitly in
//!   production).
//!
//! Credentials are operator's choice:
//!
//! - **Local dev**: [`AzureKvSigner::connect`] uses
//!   [`DeveloperToolsCredential`]; run `az login` first.
//! - **AKS / Container Apps / VM Scale Sets**: build a
//!   `ManagedIdentityCredential` and call
//!   [`AzureKvSigner::connect_with_credential`].
//! - **Federated identity (GKE-style on AKS)**: build a
//!   `WorkloadIdentityCredential`.
//! - **VM / CI without managed identity**: build a
//!   `ClientSecretCredential` from `AZURE_CLIENT_ID` +
//!   `AZURE_TENANT_ID` + `AZURE_CLIENT_SECRET`.
//!
//! The Rust `azure_identity` crate at 0.30 doesn't yet ship a single
//! `DefaultAzureCredential` chain (the .NET/Python convenience wrapper
//! around the auth-method ladder). When that lands upstream we'll
//! switch [`AzureKvSigner::connect`]'s default to use it; until then,
//! production callers pick the credential explicitly.
//!
//! [`DeveloperToolsCredential`]: azure_identity::DeveloperToolsCredential
//!
//! # Invariant: no raw-key export
//!
//! [RFC 0015 §3.1 invariant 1](../../../../spec/rfcs/0015-signer-interface.md#31-the-trait)
//! forbids any path for a `Signer` to surface raw key bytes. Managed
//! HSM cannot export private bytes via any API (FIPS 140-2 Level 3
//! enforcement); no method on [`AzureKvSigner`] returns key bytes.
//!
//! # Error mapping
//!
//! See [`error`] for the full Azure HTTP → [`SignerError`] table pinned
//! by [RFC 0017 §3.4](../../../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping).
//!
//! [`Signer`]: yutha_signer::Signer
//! [`Signer::sign_message`]: yutha_signer::Signer::sign_message
//! [`SignerError`]: yutha_signer::SignerError

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod config;
mod error;
mod signer;

pub use config::AzureKvConfig;
pub use error::map_azure_error;
pub use signer::AzureKvSigner;
