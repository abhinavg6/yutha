//! HashiCorp Vault transit-engine backend for the Yutha [`Signer`] trait.
//!
//! Implements [RFC 0017 §4.1 — External Signer backends: Vault transit](../../../spec/rfcs/0017-external-signer-backends.md#41-hashicorp-vault-transit-yutha-signer-vault).
//! The signing key lives inside Vault; every [`Signer::sign_message`] call is
//! an HTTP RPC to `transit/sign/<key_name>`. The substrate never sees the
//! private bytes — they cannot leave Vault.
//!
//! Vault transit is also the recommended enterprise custody path on AWS,
//! since native AWS KMS does not support Ed25519 today
//! (see [RFC 0015 §9.1](../../../spec/rfcs/0015-signer-interface.md#91-aws-kms-ed25519-support--decided)).
//!
//! # Quick orientation
//!
//! ```no_run
//! use yutha_signer::Signer;
//! use yutha_signer_vault::{VaultAuth, VaultConfig, VaultSigner};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = VaultSigner::connect(VaultConfig {
//!     address: "https://vault.internal:8200".into(),
//!     mount: "transit".into(),
//!     key_name: "yutha-bootstrap".into(),
//!     auth: VaultAuth::Token("hvs.…".into()),
//!     namespace: None,
//! })
//! .await?;
//!
//! // The public key was fetched once at `connect()` and is cached; the
//! // first `sign_message` call is the first network RPC after connect.
//! let pk = signer.public_key();
//! let sig = signer.sign_message(b"hello vault").await?;
//! // `sig` verifies under `pk` per RFC 8032.
//! # Ok(()) }
//! ```
//!
//! # Operator surface (env-var convention)
//!
//! Per RFC 0017 §3.2, the env-var prefix for this backend is
//! `YUTHA_SIGNER_VAULT_*`. [`VaultConfig::from_env`] populates the config from:
//!
//! - `YUTHA_SIGNER_VAULT_ADDR` — Vault HTTPS URL (required).
//! - `YUTHA_SIGNER_VAULT_MOUNT` — transit mount path (default `transit`).
//! - `YUTHA_SIGNER_VAULT_KEY` — transit key name (required).
//! - `YUTHA_SIGNER_VAULT_NAMESPACE` — Vault Enterprise namespace (optional).
//! - One of:
//!   - `YUTHA_SIGNER_VAULT_TOKEN` — root/static token (dev + small ops).
//!   - `YUTHA_SIGNER_VAULT_APPROLE_ROLE_ID` + `_SECRET_ID` (+ optional `_MOUNT`) — AppRole.
//!
//! Kubernetes and AWS IAM auth methods are reserved by the trait shape but
//! return [`SignerError::UnsupportedAlgorithm`] in v1 — they land in a
//! follow-on PR with their own integration test coverage. See §4 of the
//! crate-level docs / `README.md` for the planned env-var matrix.
//!
//! # Invariant: no raw-key export
//!
//! [RFC 0015 §3.1 invariant 1](../../../spec/rfcs/0015-signer-interface.md#31-the-trait)
//! forbids any path for a `Signer` to surface raw key bytes. This crate is
//! structurally incapable of violating that invariant: the private key never
//! leaves Vault, no method on [`VaultSigner`] returns key bytes, and the
//! hand-rolled `Debug` impl redacts auth credentials.
//!
//! # Error mapping
//!
//! See [`error`] for the full Vault-HTTP → [`SignerError`] table pinned by
//! [RFC 0017 §3.4](../../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping).
//! Short version:
//!
//! | Vault response             | Variant                          |
//! |----------------------------|----------------------------------|
//! | 401 / 403 (auth)           | `BackendRejected`                |
//! | 404 (key missing)          | `BackendRejected`                |
//! | 5xx / connection / timeout | `BackendUnavailable` (retryable) |
//! | Non-Ed25519 key            | `UnsupportedAlgorithm`           |
//! | Anything else              | `Internal`                       |
//!
//! [`Signer`]: yutha_signer::Signer
//! [`Signer::sign_message`]: yutha_signer::Signer::sign_message
//! [`SignerError`]: yutha_signer::SignerError

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod auth;
mod config;
mod error;
mod signer;

pub use auth::VaultAuth;
pub use config::VaultConfig;
pub use error::map_client_error;
pub use signer::VaultSigner;
