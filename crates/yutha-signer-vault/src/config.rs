//! [`VaultConfig`] — the construction-time configuration for a [`VaultSigner`].
//!
//! Mirrors the env-var convention from RFC 0017 §3.2:
//! `YUTHA_SIGNER_VAULT_{ADDR,MOUNT,KEY,NAMESPACE}` plus the auth-method
//! variant prefix (`YUTHA_SIGNER_VAULT_TOKEN` /
//! `YUTHA_SIGNER_VAULT_APPROLE_*`).
//!
//! [`VaultSigner`]: crate::VaultSigner

use crate::auth::VaultAuth;
use std::env;
use yutha_signer::SignerError;

/// Construction-time configuration for [`VaultSigner`](crate::VaultSigner).
///
/// All fields are inspected exactly once at [`VaultSigner::connect`] time;
/// changing them after connect has no effect (the cached public key + auth
/// token are baked into the running signer).
///
/// # Naming convention
///
/// Yutha names the *key* (e.g. `yutha-bootstrap`), not the full Vault path.
/// The Vault transit endpoints (`/transit/keys/<key>` and
/// `/transit/sign/<key>`) are derived from [`VaultConfig::mount`] +
/// [`VaultConfig::key_name`].
///
/// [`VaultSigner::connect`]: crate::VaultSigner::connect
#[derive(Clone)]
pub struct VaultConfig {
    /// Vault HTTPS endpoint, e.g. `https://vault.internal:8200`.
    ///
    /// Plain `http://` is supported for local dev / `vault server -dev` but
    /// is logged as a warning at `connect()` time so operators don't ship
    /// production with it.
    pub address: String,
    /// Mount path of the transit secrets engine, typically `transit`.
    ///
    /// If your operator mounted the engine elsewhere (e.g. `transit-yutha`
    /// for tenant isolation), set this to that path. No leading or trailing
    /// slash.
    pub mount: String,
    /// Name of the Ed25519 transit key Yutha will sign with.
    ///
    /// Created by the operator out-of-band via e.g.
    /// `vault write -f transit/keys/<key_name> type=ed25519` before
    /// `connect()` is called.
    pub key_name: String,
    /// Authentication method to obtain the Vault client token. See
    /// [`VaultAuth`] for the supported methods.
    pub auth: VaultAuth,
    /// Vault Enterprise namespace (`X-Vault-Namespace` header). Set to
    /// `Some(...)` if the operator has scoped the transit key to a
    /// non-root namespace; `None` for OSS Vault or the root namespace.
    pub namespace: Option<String>,
}

impl std::fmt::Debug for VaultConfig {
    /// Redacts the auth credential so `tracing::debug!(?config)` is safe.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("address", &self.address)
            .field("mount", &self.mount)
            .field("key_name", &self.key_name)
            .field("auth", &self.auth) // VaultAuth's Debug redacts secrets
            .field("namespace", &self.namespace)
            .finish()
    }
}

impl VaultConfig {
    /// Populate from the `YUTHA_SIGNER_VAULT_*` env-var convention pinned by
    /// [RFC 0017 §3.2](../../../../spec/rfcs/0017-external-signer-backends.md#32-construction-and-config).
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::Internal`] with a `missing env var <NAME>`
    /// message when a required variable is absent. Operators see the
    /// missing variable name in their logs, which is more useful than a
    /// generic "configuration error".
    pub fn from_env() -> Result<Self, SignerError> {
        let address = require_env("YUTHA_SIGNER_VAULT_ADDR")?;
        let mount = env::var("YUTHA_SIGNER_VAULT_MOUNT").unwrap_or_else(|_| "transit".to_string());
        let key_name = require_env("YUTHA_SIGNER_VAULT_KEY")?;
        let namespace = env::var("YUTHA_SIGNER_VAULT_NAMESPACE").ok();
        let auth = VaultAuth::from_env()?;

        Ok(Self {
            address,
            mount,
            key_name,
            auth,
            namespace,
        })
    }
}

fn require_env(name: &str) -> Result<String, SignerError> {
    env::var(name).map_err(|_| SignerError::Internal(format!("missing env var {name}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_token() {
        let cfg = VaultConfig {
            address: "https://vault.local:8200".into(),
            mount: "transit".into(),
            key_name: "my-key".into(),
            auth: VaultAuth::Token("hvs.SECRET".into()),
            namespace: None,
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("SECRET"), "Debug must redact token bytes");
        assert!(dbg.contains("my-key"), "Debug must include key name");
    }
}
