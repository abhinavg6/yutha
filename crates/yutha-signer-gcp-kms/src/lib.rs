//! Google Cloud KMS backend for the Yutha [`Signer`] trait.
//!
//! Implements [RFC 0017 §4.2 — External Signer backends: GCP KMS](../../../spec/rfcs/0017-external-signer-backends.md#42-gcp-kms-yutha-signer-gcp-kms).
//! The signing key lives inside Google Cloud KMS (algorithm
//! `EC_SIGN_ED25519` — EdDSA on Curve25519 in PureEdDSA mode); every
//! [`Signer::sign_message`] call is a gRPC round-trip to
//! `cryptoKeyVersions.asymmetricSign`. The substrate never sees the
//! private bytes — they cannot leave GCP's HSM (or its software KMS
//! boundary, depending on the protection level operators picked).
//!
//! # Quick orientation
//!
//! ```no_run
//! use yutha_signer::Signer;
//! use yutha_signer_gcp_kms::{GcpKmsConfig, GcpKmsSigner};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = GcpKmsSigner::connect(GcpKmsConfig {
//!     key_version_name:
//!         "projects/yutha-prod/locations/us-central1/keyRings/yutha/cryptoKeys/bootstrap/cryptoKeyVersions/1".into(),
//!     endpoint: None,
//! })
//! .await?;
//!
//! let pk = signer.public_key();
//! let sig = signer.sign_message(b"hello cloud").await?;
//! # Ok(()) }
//! ```
//!
//! # Operator surface (env-var convention)
//!
//! Per RFC 0017 §3.2, the env-var prefix for this backend is
//! `YUTHA_SIGNER_GCP_KMS_*`. [`GcpKmsConfig::from_env`] populates the
//! config from:
//!
//! - `YUTHA_SIGNER_GCP_KMS_KEY_VERSION` — the full resource path
//!   `projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}/cryptoKeyVersions/{v}`
//!   (required). Yutha names the *exact version* — rotation is
//!   operator-controlled per [RFC 0017 §3.6](../../../spec/rfcs/0017-external-signer-backends.md#36-rotation-and-key-versions).
//! - `YUTHA_SIGNER_GCP_KMS_ENDPOINT` — override the default Cloud KMS
//!   endpoint (`https://cloudkms.googleapis.com`); useful for regional
//!   endpoints or for proxying through a VPC Service Controls perimeter.
//!
//! Credentials come from Application Default Credentials — set
//! `GOOGLE_APPLICATION_CREDENTIALS` to the path of a service-account
//! JSON key, run `gcloud auth application-default login` for local dev,
//! or attach a Workload Identity to your GKE / Cloud Run / GCE workload.
//! The SDK handles the rest; no Yutha-side credential plumbing.
//!
//! # Invariant: no raw-key export
//!
//! [RFC 0015 §3.1 invariant 1](../../../../spec/rfcs/0015-signer-interface.md#31-the-trait)
//! forbids any path for a `Signer` to surface raw key bytes. This crate
//! is structurally incapable of violating that invariant: GCP KMS does
//! not expose private key material via any API, and no method on
//! [`GcpKmsSigner`] returns key bytes.
//!
//! # Error mapping
//!
//! See [`error`] for the full gRPC-status → [`SignerError`] table pinned
//! by [RFC 0017 §3.4](../../../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping).
//! Short version:
//!
//! | gRPC status                                | Variant                          |
//! |--------------------------------------------|----------------------------------|
//! | `PERMISSION_DENIED` / `UNAUTHENTICATED`    | `BackendRejected`                |
//! | `NOT_FOUND` (key version missing)          | `BackendRejected`                |
//! | `FAILED_PRECONDITION` (wrong algorithm)    | `BackendRejected` (or `UnsupportedAlgorithm` when caught at connect-time) |
//! | `UNAVAILABLE` / `DEADLINE_EXCEEDED` / transport | `BackendUnavailable` (retryable) |
//! | Non-`EC_SIGN_ED25519` key                  | `UnsupportedAlgorithm`           |
//! | Anything else                              | `Internal`                       |
//!
//! [`Signer`]: yutha_signer::Signer
//! [`Signer::sign_message`]: yutha_signer::Signer::sign_message
//! [`SignerError`]: yutha_signer::SignerError

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod config;
mod error;
mod signer;

pub use config::GcpKmsConfig;
pub use error::map_kms_error;
pub use signer::GcpKmsSigner;
