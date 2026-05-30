//! [`VaultAuth`] — supported Vault authentication methods.
//!
//! Per RFC 0017 §3.4, every backend MUST explicitly enumerate its supported
//! auth methods. For v1, this crate ships **Token** + **AppRole** end-to-end
//! and reserves **Kubernetes** + **AWS IAM** as variants that return
//! [`SignerError::UnsupportedAlgorithm`] at connect time. They land in a
//! follow-on PR with their own integration test coverage; the variant exists
//! today so callers depending on the type don't break when they do land.

use std::env;
use yutha_signer::SignerError;

/// Vault authentication method.
///
/// # Variant rationale
///
/// - [`VaultAuth::Token`] is the simplest path — operator hands the process
///   a Vault token (root, periodic, or fetched out-of-band by some other
///   credentialing system) and the signer uses it directly. Most useful for
///   `vault server -dev` integration tests and for deployments where some
///   other agent (e.g. Vault Agent sidecar) handles the renewal lifecycle.
///
/// - [`VaultAuth::AppRole`] is the recommended path for cloud VMs without a
///   workload-identity story. AppRole gives the operator a `role_id` +
///   `secret_id` pair, the signer logs in once at construction, and Vault
///   returns a client token. This is the "AWS-friendly" path RFC 0015 §9.1
///   nominated.
///
/// - [`VaultAuth::Kubernetes`] and [`VaultAuth::AwsIam`] are reserved
///   variants — they're part of the v1 trait surface so callers can match
///   exhaustively, but `connect()` currently rejects them. They become
///   supported in a follow-on PR.
///
/// # Secrets handling
///
/// The hand-rolled [`std::fmt::Debug`] impl redacts every secret-bearing
/// field so accidental `tracing::debug!(?auth)` or `dbg!(&auth)` calls
/// don't leak credentials to logs.
#[derive(Clone)]
pub enum VaultAuth {
    /// A pre-acquired Vault client token. Used verbatim as the
    /// `X-Vault-Token` header on every request.
    Token(String),
    /// AppRole role_id + secret_id pair. The signer logs in once at
    /// construction (`POST <mount>/login`) and uses the returned token for
    /// subsequent requests.
    AppRole {
        /// Mount path of the AppRole auth backend. Defaults to `approle`;
        /// override with `YUTHA_SIGNER_VAULT_APPROLE_MOUNT`.
        mount: String,
        /// AppRole role_id, typically a UUID. Operator-issued.
        role_id: String,
        /// AppRole secret_id, the wrapped-or-unwrapped credential the
        /// operator provisioned.
        secret_id: String,
    },
    /// Reserved — Kubernetes service-account JWT auth. Returns
    /// [`SignerError::UnsupportedAlgorithm`] in v1.
    Kubernetes {
        /// Mount path of the Kubernetes auth backend.
        mount: String,
        /// Role name as configured in Vault.
        role: String,
        /// Service-account JWT, typically read from
        /// `/var/run/secrets/kubernetes.io/serviceaccount/token`.
        jwt: String,
    },
    /// Reserved — AWS IAM auth. Returns
    /// [`SignerError::UnsupportedAlgorithm`] in v1.
    AwsIam {
        /// Mount path of the AWS auth backend.
        mount: String,
        /// Role name as configured in Vault.
        role: String,
    },
}

impl std::fmt::Debug for VaultAuth {
    /// Hand-rolled to keep every secret-bearing field out of formatter
    /// output. Mirrors the same posture as [`crate::config::VaultConfig`]'s
    /// `Debug` impl and the [`yutha_signer::InProcessSigner`] private-bytes
    /// redaction.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"<redacted>").finish(),
            Self::AppRole { mount, .. } => f
                .debug_struct("AppRole")
                .field("mount", mount)
                .field("role_id", &"<redacted>")
                .field("secret_id", &"<redacted>")
                .finish(),
            Self::Kubernetes { mount, role, .. } => f
                .debug_struct("Kubernetes")
                .field("mount", mount)
                .field("role", role)
                .field("jwt", &"<redacted>")
                .finish(),
            Self::AwsIam { mount, role } => f
                .debug_struct("AwsIam")
                .field("mount", mount)
                .field("role", role)
                .finish(),
        }
    }
}

impl VaultAuth {
    /// Populate from the `YUTHA_SIGNER_VAULT_{TOKEN,APPROLE_*}` env-var
    /// convention pinned by [RFC 0017 §3.2](../../../../spec/rfcs/0017-external-signer-backends.md#32-construction-and-config).
    ///
    /// Precedence: Token > AppRole. Setting `YUTHA_SIGNER_VAULT_TOKEN`
    /// always wins so that operators can override the auth method
    /// temporarily (e.g. for incident response) without unsetting the
    /// AppRole env vars.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::Internal`] if neither auth method has its
    /// env vars fully set. The message lists both viable methods.
    pub fn from_env() -> Result<Self, SignerError> {
        if let Ok(token) = env::var("YUTHA_SIGNER_VAULT_TOKEN") {
            return Ok(Self::Token(token));
        }

        let role_id = env::var("YUTHA_SIGNER_VAULT_APPROLE_ROLE_ID").ok();
        let secret_id = env::var("YUTHA_SIGNER_VAULT_APPROLE_SECRET_ID").ok();
        if let (Some(role_id), Some(secret_id)) = (role_id, secret_id) {
            let mount = env::var("YUTHA_SIGNER_VAULT_APPROLE_MOUNT")
                .unwrap_or_else(|_| "approle".to_string());
            return Ok(Self::AppRole {
                mount,
                role_id,
                secret_id,
            });
        }

        Err(SignerError::Internal(
            "no Vault auth env vars set — provide either YUTHA_SIGNER_VAULT_TOKEN, \
             or YUTHA_SIGNER_VAULT_APPROLE_ROLE_ID + YUTHA_SIGNER_VAULT_APPROLE_SECRET_ID"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_every_secret() {
        let cases = [
            VaultAuth::Token("hvs.SECRET".into()),
            VaultAuth::AppRole {
                mount: "approle".into(),
                role_id: "ROLEID-SECRET".into(),
                secret_id: "SECRETID-SECRET".into(),
            },
            VaultAuth::Kubernetes {
                mount: "kubernetes".into(),
                role: "yutha".into(),
                jwt: "JWT-SECRET".into(),
            },
            VaultAuth::AwsIam {
                mount: "aws".into(),
                role: "yutha".into(),
            },
        ];
        for auth in cases {
            let dbg = format!("{auth:?}");
            assert!(
                !dbg.contains("SECRET"),
                "Debug for {auth:?} leaked SECRET: {dbg}"
            );
        }
    }
}
