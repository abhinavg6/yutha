//! [`VaultSigner`] — `Signer` impl backed by HashiCorp Vault transit.
//!
//! Implements [RFC 0017 §4.1](../../../../spec/rfcs/0017-external-signer-backends.md#41-hashicorp-vault-transit-yutha-signer-vault).
//!
//! Construction (`connect()`) does three things, in order:
//!
//! 1. Build a [`vaultrs::client::VaultClient`] against the configured address.
//! 2. Authenticate per the configured [`VaultAuth`] variant; for AppRole this
//!    is a `POST <mount>/login` round-trip that returns a `client_token`,
//!    which is then plugged back into the client.
//! 3. `GET <mount>/keys/<key_name>` to discover the Ed25519 public key and
//!    cache it. After this point [`Signer::public_key`] is sync and free.
//!
//! [`Signer::sign_message`] then becomes a single `POST <mount>/sign/<key>`
//! per call, base64-encoding the message on the way in and base64-decoding
//! Vault's `vault:v<version>:<sig>` envelope on the way out.

use crate::auth::VaultAuth;
use crate::config::VaultConfig;
use crate::error::map_client_error;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use vaultrs::{
    // The `Client as _` import brings the trait's `set_token` method into
    // scope at module level so the AppRole branch in `connect()` can call
    // it without scaffolding a per-call `use`. We don't need the trait
    // by name anywhere — the underscore alias keeps it out of the
    // crate's name resolution surface.
    client::{Client as _, VaultClient, VaultClientSettingsBuilder},
    transit,
};
use yutha_core::{PublicKey, Signature, SignatureAlgorithm};
use yutha_signer::{Signer, SignerError};

/// `Signer` implementation that delegates Ed25519 signing to a HashiCorp
/// Vault transit-engine key. The private key never leaves Vault.
///
/// See the crate-level docs for the overall posture; see
/// [`VaultSigner::connect`] for the construction flow.
pub struct VaultSigner {
    /// The authenticated Vault client. Held behind an `Arc` so the same
    /// signer instance can be shared across tasks without per-call cloning
    /// of the underlying `reqwest` stack.
    client: Arc<VaultClient>,
    /// Transit mount path (e.g. `transit`).
    mount: String,
    /// Transit key name (e.g. `yutha-bootstrap`).
    key_name: String,
    /// The Ed25519 public key, fetched once at `connect()` and cached.
    /// Per [RFC 0015 §3.1 invariant 3](../../../../spec/rfcs/0015-signer-interface.md#31-the-trait),
    /// `Signer::public_key` MUST be sync + infallible.
    public_key: PublicKey,
}

impl std::fmt::Debug for VaultSigner {
    /// Hand-rolled so the inner `VaultClient` (which holds the auth token
    /// in its middleware) is summarised rather than fully rendered. The
    /// public key is small + non-secret so it's safe to print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSigner")
            .field("mount", &self.mount)
            .field("key_name", &self.key_name)
            .field("public_key", &self.public_key)
            .field("client", &"<vaultrs::VaultClient redacted>")
            .finish()
    }
}

impl VaultSigner {
    /// Connect to Vault, authenticate, and fetch the Ed25519 public key.
    ///
    /// All three steps happen here so that:
    /// - [`Signer::public_key`] can be sync + infallible per the trait
    ///   contract (no network call on the hot path);
    /// - operators see auth + key-fetch failures at process startup, where
    ///   a supervisor / orchestrator can restart cleanly, rather than at
    ///   the first `sign_message` call deep in some agent's lifecycle.
    ///
    /// # Errors
    ///
    /// - [`SignerError::Internal`] for URL parse errors or for the
    ///   reserved-but-unimplemented auth variants ([`VaultAuth::Kubernetes`]
    ///   / [`VaultAuth::AwsIam`]).
    /// - [`SignerError::BackendRejected`] for 401 / 403 / 404 from Vault
    ///   (bad token, missing key, missing policy).
    /// - [`SignerError::BackendUnavailable`] for 5xx, network errors,
    ///   timeouts.
    /// - [`SignerError::UnsupportedAlgorithm`] if the transit key resolves
    ///   to a non-Ed25519 type, or if Vault returns an unexpected key shape.
    pub async fn connect(config: VaultConfig) -> Result<Self, SignerError> {
        if config.address.starts_with("http://") {
            tracing::warn!(
                address = %config.address,
                "yutha-signer-vault connecting over plain HTTP — supported for dev only; \
                 use HTTPS in production"
            );
        }

        let mut settings_builder = VaultClientSettingsBuilder::default();
        settings_builder.address(&config.address);
        if let Some(ns) = &config.namespace {
            settings_builder.set_namespace(ns.clone());
        }
        // Token will be set after auth flow; for Token auth we pre-populate.
        if let VaultAuth::Token(token) = &config.auth {
            settings_builder.token(token.clone());
        }
        let settings = settings_builder
            .build()
            .map_err(|e| SignerError::Internal(format!("invalid Vault settings: {e}")))?;

        let mut client = VaultClient::new(settings).map_err(|e| {
            SignerError::Internal(format!("failed to build VaultClient: {e}"))
        })?;

        // Auth methods that need a login round-trip do it here, then plug
        // the returned client_token back into the client.
        match &config.auth {
            VaultAuth::Token(_) => {
                // Already set on the settings builder above; nothing to do.
            }
            VaultAuth::AppRole {
                mount,
                role_id,
                secret_id,
            } => {
                let auth_info =
                    vaultrs::auth::approle::login(&client, mount, role_id, secret_id)
                        .await
                        .map_err(|e| map_client_error(e, "approle login"))?;
                // `VaultrsClient::set_token` is the trait method that
                // updates both `client.settings.token` and the middleware
                // header. Imported at module-level to keep the call site
                // scope-free.
                client.set_token(&auth_info.client_token);
            }
            VaultAuth::Kubernetes { .. } | VaultAuth::AwsIam { .. } => {
                return Err(SignerError::UnsupportedAlgorithm(
                    "VaultAuth::Kubernetes and VaultAuth::AwsIam are reserved \
                     variants in v1; they land in a follow-on PR with their \
                     own integration coverage. Use Token or AppRole today."
                        .into(),
                ));
            }
        }

        // Fetch + cache the public key BEFORE wrapping in `Arc`; the helper
        // needs `&VaultClient`, and threading an `Arc` through it would just
        // force a deref at the call site.
        let public_key = fetch_public_key(&client, &config.mount, &config.key_name).await?;
        let client = Arc::new(client);

        tracing::info!(
            mount = %config.mount,
            key_name = %config.key_name,
            address = %config.address,
            "yutha-signer-vault connected"
        );

        Ok(Self {
            client,
            mount: config.mount,
            key_name: config.key_name,
            public_key,
        })
    }
}

/// `GET <mount>/keys/<name>` + algorithm + shape validation.
///
/// Returns the latest-version Ed25519 public key as a [`PublicKey`].
/// Surfaces [`SignerError::UnsupportedAlgorithm`] when:
/// - the transit key's `type` is not `ed25519`;
/// - the `keys` payload is symmetric (Vault returned only timestamps, no
///   public-key material — e.g. someone pointed us at an AES key);
/// - the highest-versioned public-key entry doesn't base64-decode to
///   exactly 32 bytes.
async fn fetch_public_key(
    client: &VaultClient,
    mount: &str,
    name: &str,
) -> Result<PublicKey, SignerError> {
    use vaultrs::api::transit::{responses::ReadKeyData, KeyType};

    let response = transit::key::read(client, mount, name)
        .await
        .map_err(|e| map_client_error(e, "transit key read"))?;

    if !matches!(response.key_type, KeyType::Ed25519) {
        return Err(SignerError::UnsupportedAlgorithm(format!(
            "vault transit key '{name}' is type {:?}; only ed25519 is supported \
             (RFC 0015 §3.1 invariant 2 pins the algorithm)",
            response.key_type
        )));
    }

    let asymmetric_keys = match response.keys {
        ReadKeyData::Asymmetric(map) => map,
        ReadKeyData::Symmetric(_) => {
            return Err(SignerError::UnsupportedAlgorithm(format!(
                "vault transit key '{name}' returned symmetric-key metadata \
                 even though key_type was Ed25519; refusing to proceed"
            )));
        }
    };

    // Pick the highest-numbered key version. Vault transit's read response
    // has no explicit "latest_version" field; the convention is the largest
    // version key in the map.
    let (latest_version, entry) = asymmetric_keys
        .iter()
        .filter_map(|(k, v)| k.parse::<u64>().ok().map(|n| (n, v)))
        .max_by_key(|(n, _)| *n)
        .ok_or_else(|| {
            SignerError::Internal(format!(
                "vault transit key '{name}' returned no key versions"
            ))
        })?;

    // Vault returns the Ed25519 public key as PEM-wrapped Subject Public Key
    // Info (SPKI). The raw 32-byte key sits at the end. We accept both
    // shapes: PEM (real Vault) and bare base64-of-32-bytes (some mocks /
    // older Vault revs).
    let pk_bytes = decode_ed25519_public_key(&entry.public_key).ok_or_else(|| {
        SignerError::UnsupportedAlgorithm(format!(
            "vault transit key '{name}' v{latest_version} returned an Ed25519 \
             public key that did not decode to 32 bytes"
        ))
    })?;

    PublicKey::new(SignatureAlgorithm::Ed25519, pk_bytes)
        .map_err(|e| SignerError::Internal(format!("invalid public-key bytes from Vault: {e}")))
}

/// Decode an Ed25519 public key from Vault's representation.
///
/// Vault transit returns the public key as PEM-wrapped X.509 SubjectPublicKeyInfo
/// (SPKI), where the last 32 bytes of the DER-decoded body are the raw Ed25519
/// public key (the SPKI header for Ed25519 is fixed-shape: 12 bytes of ASN.1
/// preamble + the 32-byte key, total 44 bytes).
///
/// To stay self-contained (no `pem` or `x509-cert` dep), we parse minimally:
///
/// - Strip `-----BEGIN PUBLIC KEY-----` + `-----END PUBLIC KEY-----` and any
///   whitespace.
/// - Base64-decode the body.
/// - Take the last 32 bytes if the result is 44 bytes (the SPKI shape) or
///   accept it verbatim if it's already 32 bytes (raw-key shape from older
///   Vault versions / mocks).
///
/// Returns `None` if the decode doesn't land on a 32-byte key.
fn decode_ed25519_public_key(encoded: &str) -> Option<Vec<u8>> {
    let body: String = encoded
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    let bytes = B64.decode(body.as_bytes()).ok()?;

    match bytes.len() {
        32 => Some(bytes),
        // SPKI envelope: 12-byte ASN.1 prefix + 32-byte raw key.
        44 => Some(bytes[12..].to_vec()),
        _ => None,
    }
}

#[async_trait]
impl Signer for VaultSigner {
    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // Vault transit sign requires base64-encoded input. Ed25519 in Vault
        // does NOT support `prehashed=true` — we send the canonical bytes
        // and Vault internally does the EdDSA sign-on-message.
        let input_b64 = B64.encode(message);

        // `transit::data::sign` takes `&impl Client`; `&*self.client`
        // derefs `Arc<VaultClient>` to `&VaultClient`.
        let response =
            transit::data::sign(&*self.client, &self.mount, &self.key_name, &input_b64, None)
                .await
                .map_err(|e| map_client_error(e, "transit sign"))?;

        // Response wire format: `vault:v<version>:<base64-signature>`.
        // We don't currently surface the version number (callers don't need
        // it — the signature is self-contained and the public key is
        // pinned at connect time). Strip the prefix + decode.
        let sig_b64 = response
            .signature
            .splitn(3, ':')
            .nth(2)
            .ok_or_else(|| {
                SignerError::Internal(format!(
                    "vault returned malformed signature envelope: {}",
                    response.signature
                ))
            })?;

        let sig_bytes = B64
            .decode(sig_b64.as_bytes())
            .map_err(|e| SignerError::Internal(format!("vault sig base64 decode: {e}")))?;

        let key_fingerprint = Sha256::digest(&self.public_key.value).to_vec();

        Signature::new(SignatureAlgorithm::Ed25519, sig_bytes, key_fingerprint).map_err(|e| {
            SignerError::Internal(format!(
                "vault returned signature bytes that did not pass length check: {e}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bare-32-bytes base64 — what older Vault / test mocks may return.
    #[test]
    fn decode_ed25519_public_key_bare() {
        let pk_bytes = vec![0xAA_u8; 32];
        let encoded = B64.encode(&pk_bytes);
        let decoded = decode_ed25519_public_key(&encoded).expect("must decode");
        assert_eq!(decoded, pk_bytes);
    }

    /// 44-byte SPKI body — Ed25519 SPKI is a 12-byte prefix + 32-byte key.
    /// We don't validate the prefix bytes (the algorithm OID), just that
    /// the trailing 32 are returned. Vault has already validated this on
    /// its side.
    #[test]
    fn decode_ed25519_public_key_spki_44_body() {
        let mut spki = vec![0u8; 12];
        spki.extend_from_slice(&[0x42_u8; 32]);
        let encoded = B64.encode(&spki);
        let decoded = decode_ed25519_public_key(&encoded).expect("must decode");
        assert_eq!(decoded, vec![0x42_u8; 32]);
    }

    /// Full PEM envelope — what real Vault returns.
    #[test]
    fn decode_ed25519_public_key_pem_envelope() {
        let mut spki = vec![0u8; 12];
        spki.extend_from_slice(&[0x7F_u8; 32]);
        let body = B64.encode(&spki);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n",
        );
        let decoded = decode_ed25519_public_key(&pem).expect("must decode");
        assert_eq!(decoded, vec![0x7F_u8; 32]);
    }

    /// Wrong length → None, surfaces as UnsupportedAlgorithm at the caller.
    #[test]
    fn decode_ed25519_public_key_wrong_length() {
        let wrong = B64.encode([0u8; 31]);
        assert!(decode_ed25519_public_key(&wrong).is_none());
        let wronger = B64.encode([0u8; 64]);
        assert!(decode_ed25519_public_key(&wronger).is_none());
    }
}
