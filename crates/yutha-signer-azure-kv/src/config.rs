//! [`AzureKvConfig`] — the construction-time configuration for an
//! [`AzureKvSigner`].
//!
//! Mirrors the env-var convention from RFC 0017 §3.2:
//! `YUTHA_SIGNER_AZURE_KV_{VAULT_URL,KEY_NAME,KEY_VERSION}`.
//!
//! [`AzureKvSigner`]: crate::AzureKvSigner

use std::env;
use yutha_signer::SignerError;

/// Construction-time configuration for [`AzureKvSigner`](crate::AzureKvSigner).
///
/// All fields are inspected exactly once at [`AzureKvSigner::connect`]
/// time; changing them after connect has no effect (the cached public
/// key + token are baked into the running signer).
///
/// # Tier requirement
///
/// `vault_url` MUST point at an Azure Managed HSM
/// (`https://<name>.managedhsm.azure.net`); standard Key Vault
/// (`*.vault.azure.net`) does not support Ed25519. The crate emits a
/// warning at connect time when the URL doesn't match the Managed HSM
/// shape, and the underlying `connect()` call will fail with
/// [`SignerError::UnsupportedAlgorithm`] when it sees the wrong key
/// type.
///
/// [`AzureKvSigner::connect`]: crate::AzureKvSigner::connect
#[derive(Clone, Debug)]
pub struct AzureKvConfig {
    /// Full HTTPS URL of the Managed HSM, e.g.
    /// `https://yutha-hsm.managedhsm.azure.net`. No trailing slash
    /// required; the SDK normalises.
    pub vault_url: String,
    /// Name of the Ed25519 key inside the HSM.
    pub key_name: String,
    /// Explicit key-version hex string (32 hex chars typical), or
    /// `None` to use the latest version.
    ///
    /// **Strongly recommended in production.** Pinning the version
    /// means rotation is operator-controlled per [RFC 0017 §3.6](../../../../spec/rfcs/0017-external-signer-backends.md#36-rotation-and-key-versions);
    /// `None` lets Azure auto-rotate the underlying key behind your
    /// back, which can invalidate previously-issued signatures from
    /// the point of view of any verifier that cached the old public
    /// key.
    pub key_version: Option<String>,
}

impl AzureKvConfig {
    /// Populate from the `YUTHA_SIGNER_AZURE_KV_*` env-var convention
    /// pinned by [RFC 0017 §3.2](../../../../spec/rfcs/0017-external-signer-backends.md#32-construction-and-config).
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::Internal`] with a `missing env var <NAME>`
    /// message when a required variable is absent or when the vault URL
    /// fails the basic shape check.
    pub fn from_env() -> Result<Self, SignerError> {
        let vault_url = env::var("YUTHA_SIGNER_AZURE_KV_VAULT_URL").map_err(|_| {
            SignerError::Internal("missing env var YUTHA_SIGNER_AZURE_KV_VAULT_URL".into())
        })?;
        let key_name = env::var("YUTHA_SIGNER_AZURE_KV_KEY_NAME").map_err(|_| {
            SignerError::Internal("missing env var YUTHA_SIGNER_AZURE_KV_KEY_NAME".into())
        })?;
        let key_version = env::var("YUTHA_SIGNER_AZURE_KV_KEY_VERSION").ok();
        Self::new(vault_url, key_name, key_version)
    }

    /// Validated constructor — the codepath every other entry-point
    /// goes through.
    ///
    /// Factored out of [`from_env`] so the URL-shape check is testable
    /// in unit tests without touching process env vars.
    pub fn new(
        vault_url: String,
        key_name: String,
        key_version: Option<String>,
    ) -> Result<Self, SignerError> {
        if !vault_url.starts_with("https://") {
            return Err(SignerError::Internal(format!(
                "vault_url must be an HTTPS URL; got: {vault_url}"
            )));
        }
        if key_name.is_empty() {
            return Err(SignerError::Internal("key_name must not be empty".into()));
        }
        Ok(Self {
            vault_url,
            key_name,
            key_version,
        })
    }

    /// `true` if the vault URL points at a Managed HSM; `false`
    /// otherwise (typically `*.vault.azure.net`, which does not
    /// support Ed25519).
    ///
    /// Used by [`AzureKvSigner::connect`] to emit a warning at startup
    /// when an operator points us at the wrong tier — the failure that
    /// follows from `get_key` is hard to interpret without that hint.
    ///
    /// [`AzureKvSigner::connect`]: crate::AzureKvSigner::connect
    pub fn looks_like_managed_hsm(&self) -> bool {
        self.vault_url.contains(".managedhsm.azure.net")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_non_https_url() {
        let err = AzureKvConfig::new(
            "http://yutha-hsm.managedhsm.azure.net".into(),
            "bootstrap".into(),
            None,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("HTTPS"));
    }

    #[test]
    fn new_rejects_empty_key_name() {
        let err = AzureKvConfig::new(
            "https://yutha-hsm.managedhsm.azure.net".into(),
            String::new(),
            None,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("key_name"));
    }

    #[test]
    fn looks_like_managed_hsm_true_for_managedhsm_host() {
        let cfg = AzureKvConfig::new(
            "https://yutha-hsm.managedhsm.azure.net".into(),
            "bootstrap".into(),
            Some("v1".into()),
        )
        .unwrap();
        assert!(cfg.looks_like_managed_hsm());
    }

    #[test]
    fn looks_like_managed_hsm_false_for_standard_keyvault_host() {
        let cfg = AzureKvConfig::new(
            "https://yutha-kv.vault.azure.net".into(),
            "bootstrap".into(),
            None,
        )
        .unwrap();
        assert!(!cfg.looks_like_managed_hsm());
    }

    #[test]
    fn version_passes_through() {
        let cfg = AzureKvConfig::new(
            "https://yutha-hsm.managedhsm.azure.net".into(),
            "bootstrap".into(),
            Some("a1b2c3d4e5f6".into()),
        )
        .unwrap();
        assert_eq!(cfg.key_version.as_deref(), Some("a1b2c3d4e5f6"));
    }
}
