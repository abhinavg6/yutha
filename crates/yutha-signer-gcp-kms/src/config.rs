//! [`GcpKmsConfig`] — the construction-time configuration for a [`GcpKmsSigner`].
//!
//! Mirrors the env-var convention from RFC 0017 §3.2:
//! `YUTHA_SIGNER_GCP_KMS_KEY_VERSION` (required) +
//! `YUTHA_SIGNER_GCP_KMS_ENDPOINT` (optional).
//!
//! [`GcpKmsSigner`]: crate::GcpKmsSigner

use std::env;
use yutha_signer::SignerError;

/// Construction-time configuration for [`GcpKmsSigner`](crate::GcpKmsSigner).
///
/// All fields are inspected exactly once at [`GcpKmsSigner::connect`] time;
/// changing them after connect has no effect (the public key + auth token
/// are baked into the running signer).
///
/// [`GcpKmsSigner::connect`]: crate::GcpKmsSigner::connect
#[derive(Clone, Debug)]
pub struct GcpKmsConfig {
    /// Full resource path of the Cloud KMS crypto key *version*, e.g.
    /// `projects/yutha-prod/locations/us-central1/keyRings/yutha/cryptoKeys/bootstrap/cryptoKeyVersions/1`.
    ///
    /// Yutha names the *exact version* — pinning a specific version
    /// means rotation is operator-controlled per
    /// [RFC 0017 §3.6](../../../../spec/rfcs/0017-external-signer-backends.md#36-rotation-and-key-versions).
    /// Versions can be advanced by creating a new version in KMS and
    /// restarting the control plane with the updated config.
    pub key_version_name: String,
    /// Override the default Cloud KMS endpoint
    /// (`https://cloudkms.googleapis.com`). Useful for regional
    /// endpoints (e.g. `https://us-central1-cloudkms.googleapis.com`)
    /// or for proxying through a VPC Service Controls perimeter.
    pub endpoint: Option<String>,
}

impl GcpKmsConfig {
    /// Populate from the `YUTHA_SIGNER_GCP_KMS_*` env-var convention
    /// pinned by [RFC 0017 §3.2](../../../../spec/rfcs/0017-external-signer-backends.md#32-construction-and-config).
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::Internal`] with a `missing env var <NAME>`
    /// message when a required variable is absent, or a "must include
    /// /cryptoKeyVersions/" message when the resource path doesn't pin
    /// an explicit version.
    pub fn from_env() -> Result<Self, SignerError> {
        let key_version_name = env::var("YUTHA_SIGNER_GCP_KMS_KEY_VERSION").map_err(|_| {
            SignerError::Internal("missing env var YUTHA_SIGNER_GCP_KMS_KEY_VERSION".into())
        })?;
        let endpoint = env::var("YUTHA_SIGNER_GCP_KMS_ENDPOINT").ok();
        Self::new(key_version_name, endpoint)
    }

    /// Validated constructor — the codepath every other entry-point
    /// goes through.
    ///
    /// Factored out of [`from_env`] so the resource-path-shape check is
    /// testable in unit tests without touching process env vars
    /// (`std::env::set_var` is `unsafe` in Rust 1.86+ and this crate
    /// `#![forbid(unsafe_code)]`).
    ///
    /// The check catches typo'd resource paths at startup rather than
    /// at the first sign call. The full Cloud KMS resource format is 8
    /// segments: `projects/X/locations/X/keyRings/X/cryptoKeys/X/cryptoKeyVersions/X`.
    pub fn new(key_version_name: String, endpoint: Option<String>) -> Result<Self, SignerError> {
        if !key_version_name.contains("/cryptoKeyVersions/") {
            return Err(SignerError::Internal(format!(
                "key_version_name must include /cryptoKeyVersions/<version>; got: {key_version_name}"
            )));
        }
        Ok(Self {
            key_version_name,
            endpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_path_without_version() {
        let err = GcpKmsConfig::new(
            "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(),
            None,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("cryptoKeyVersions"));
    }

    #[test]
    fn new_accepts_full_version_path() {
        let cfg = GcpKmsConfig::new(
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1".into(),
            None,
        )
        .expect("full version path must validate");
        assert!(cfg.key_version_name.ends_with("/cryptoKeyVersions/1"));
        assert!(cfg.endpoint.is_none());
    }

    #[test]
    fn new_passes_endpoint_through() {
        let cfg = GcpKmsConfig::new(
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2".into(),
            Some("https://us-central1-cloudkms.googleapis.com".into()),
        )
        .unwrap();
        assert_eq!(
            cfg.endpoint.as_deref(),
            Some("https://us-central1-cloudkms.googleapis.com")
        );
    }
}
