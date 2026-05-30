//! [`GcpKmsSigner`] — `Signer` impl backed by Google Cloud KMS.
//!
//! Implements [RFC 0017 §4.2](../../../../spec/rfcs/0017-external-signer-backends.md#42-gcp-kms-yutha-signer-gcp-kms).
//!
//! Construction (`connect()`) does three things, in order:
//!
//! 1. Build a [`KeyManagementService`] client (the official
//!    `google-cloud-kms-v1` SDK auto-discovers ADC; no manual auth).
//! 2. `cryptoKeyVersions.getPublicKey` to fetch the Ed25519 public key
//!    PEM + algorithm assertion. The algorithm MUST be `EC_SIGN_ED25519`
//!    — anything else fails at connect-time with
//!    [`SignerError::UnsupportedAlgorithm`].
//! 3. Decode the PEM SubjectPublicKeyInfo to 32 raw Ed25519 bytes and
//!    cache them. After this point [`Signer::public_key`] is sync.
//!
//! [`Signer::sign_message`] then becomes a single
//! `cryptoKeyVersions.asymmetricSign` gRPC call per signing event. The
//! response carries the signature as a raw 64-byte `Bytes`; Yutha
//! converts it to its standard [`Signature`] value type with the
//! key-fingerprint computed once at connect.

use crate::config::GcpKmsConfig;
use crate::error::map_kms_error;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use yutha_core::{PublicKey, Signature, SignatureAlgorithm};
use yutha_signer::{Signer, SignerError};

/// `Signer` implementation that delegates Ed25519 signing to a Google
/// Cloud KMS crypto key version. The private key never leaves GCP.
///
/// See the crate-level docs for the overall posture; see
/// [`GcpKmsSigner::connect`] for the construction flow.
pub struct GcpKmsSigner {
    /// The authenticated GCP KMS client. The SDK already wraps its
    /// internal connection pool in an `Arc`, so cloning the client is
    /// cheap; we still wrap in `Arc` so the same signer instance can
    /// share the client across tasks without taking ownership of the
    /// client struct (handy for `Arc<dyn Signer>` use).
    client: Arc<KeyManagementService>,
    /// Full resource path of the cryptoKeyVersion this signer signs
    /// against. Used as `name` on every asymmetric_sign / get_public_key
    /// RPC.
    key_version_name: String,
    /// The Ed25519 public key, fetched once at `connect()` and cached.
    /// Per [RFC 0015 §3.1 invariant 3](../../../../../spec/rfcs/0015-signer-interface.md#31-the-trait),
    /// `Signer::public_key` MUST be sync + infallible.
    public_key: PublicKey,
    /// SHA-256 of `public_key.value`, precomputed at connect so
    /// `sign_message` doesn't re-hash on every call. Yutha's `Signature`
    /// value type carries this fingerprint on every signature.
    key_fingerprint: Vec<u8>,
}

impl std::fmt::Debug for GcpKmsSigner {
    /// Hand-rolled so the inner client (which holds the auth token in
    /// its internal stack) isn't fully rendered. The public key is
    /// small and non-secret so it's fine to print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsSigner")
            .field("key_version_name", &self.key_version_name)
            .field("public_key", &self.public_key)
            .field(
                "client",
                &"<google_cloud_kms_v1::KeyManagementService redacted>",
            )
            .finish()
    }
}

impl GcpKmsSigner {
    /// Connect to GCP KMS, fetch + algorithm-check + cache the public key.
    ///
    /// All three steps happen here so that:
    /// - [`Signer::public_key`] can be sync + infallible per the trait
    ///   contract (no network call on the hot path);
    /// - operators see ADC failures, wrong-algorithm keys, and missing
    ///   IAM bindings at process startup where a supervisor can restart
    ///   cleanly, not deep inside the first agent's lifecycle.
    ///
    /// # Errors
    ///
    /// - [`SignerError::Internal`] for SDK construction errors or for
    ///   PEM decode failures Yutha-side.
    /// - [`SignerError::BackendRejected`] for IAM denies (`PERMISSION_DENIED`,
    ///   `UNAUTHENTICATED`), missing key versions (`NOT_FOUND`), wrong
    ///   key state (`FAILED_PRECONDITION`).
    /// - [`SignerError::BackendUnavailable`] for transport errors,
    ///   `UNAVAILABLE`, `DEADLINE_EXCEEDED`.
    /// - [`SignerError::UnsupportedAlgorithm`] if the key version's
    ///   algorithm is anything other than `EC_SIGN_ED25519`.
    pub async fn connect(config: GcpKmsConfig) -> Result<Self, SignerError> {
        let mut builder = KeyManagementService::builder();
        if let Some(endpoint) = &config.endpoint {
            builder = builder.with_endpoint(endpoint.clone());
        }
        let client = builder
            .build()
            .await
            .map_err(|e| SignerError::Internal(format!("GCP KMS client build failed: {e}")))?;

        // Fetch + algorithm-check the public key.
        let pk_response = client
            .get_public_key()
            .set_name(&config.key_version_name)
            .send()
            .await
            .map_err(|e| map_kms_error(e, "GetPublicKey"))?;

        if !matches!(
            pk_response.algorithm,
            CryptoKeyVersionAlgorithm::EcSignEd25519
        ) {
            return Err(SignerError::UnsupportedAlgorithm(format!(
                "GCP KMS key version '{}' uses algorithm {:?}; only EC_SIGN_ED25519 is supported \
                 (RFC 0015 §3.1 invariant 2 pins the algorithm). Create the key with \
                 `--default-algorithm=ec-sign-ed25519`.",
                config.key_version_name, pk_response.algorithm
            )));
        }

        let pk_bytes = decode_ed25519_spki_pem(&pk_response.pem).ok_or_else(|| {
            SignerError::UnsupportedAlgorithm(format!(
                "GCP KMS key version '{}' returned an Ed25519 PEM that did not decode \
                 to 32 raw bytes; got: {} bytes after base64 decode",
                config.key_version_name,
                pk_response.pem.len()
            ))
        })?;

        let public_key = PublicKey::new(SignatureAlgorithm::Ed25519, pk_bytes).map_err(|e| {
            SignerError::Internal(format!("invalid public-key bytes from GCP KMS: {e}"))
        })?;
        let key_fingerprint = Sha256::digest(&public_key.value).to_vec();

        tracing::info!(
            key_version = %config.key_version_name,
            endpoint = ?config.endpoint,
            "yutha-signer-gcp-kms connected"
        );

        Ok(Self {
            client: Arc::new(client),
            key_version_name: config.key_version_name,
            public_key,
            key_fingerprint,
        })
    }
}

/// Decode a PEM-encoded Ed25519 SubjectPublicKeyInfo to 32 raw bytes.
///
/// GCP KMS always returns the public key as PEM-wrapped X.509 SPKI for
/// asymmetric keys (no `raw` variant for Ed25519 today). The DER body is
/// 44 bytes — a 12-byte ASN.1 preamble (SEQUENCE + AlgorithmIdentifier
/// for OID 1.3.101.112 + BIT STRING header) plus the raw 32-byte key.
///
/// Stays self-contained (no `pem` / `x509-cert` dep). Mirrors the
/// equivalent helper in `yutha-signer-vault` — when a third backend
/// also needs it, lift to a shared util crate.
///
/// Returns `None` if the decode doesn't land on a 32-byte key.
fn decode_ed25519_spki_pem(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    let bytes = B64.decode(body.as_bytes()).ok()?;

    match bytes.len() {
        // SPKI envelope: 12-byte ASN.1 prefix + 32-byte raw key.
        44 => Some(bytes[12..].to_vec()),
        // Belt-and-suspenders: accept bare 32 bytes from mocks / tests
        // that skip the SPKI wrap.
        32 => Some(bytes),
        _ => None,
    }
}

#[async_trait]
impl Signer for GcpKmsSigner {
    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // For Ed25519 (PureEdDSA mode) GCP KMS takes raw data, NOT a
        // pre-hash. The `data` field accepts up to 64KiB; canonical
        // bytes for our largest signed artefact (a capability) are
        // well under that ceiling.
        let response = self
            .client
            .asymmetric_sign()
            .set_name(&self.key_version_name)
            .set_data(bytes::Bytes::copy_from_slice(message))
            .send()
            .await
            .map_err(|e| map_kms_error(e, "AsymmetricSign"))?;

        let sig_bytes = response.signature.to_vec();

        Signature::new(
            SignatureAlgorithm::Ed25519,
            sig_bytes,
            self.key_fingerprint.clone(),
        )
        .map_err(|e| {
            SignerError::Internal(format!(
                "GCP KMS returned signature bytes that did not pass length check: {e}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 44-byte SPKI body — the standard Ed25519 SPKI shape. We don't
    /// validate the prefix bytes (the algorithm OID), just that the
    /// trailing 32 are returned. GCP KMS validated it on its side.
    #[test]
    fn decode_spki_pem_44_body() {
        let mut spki = vec![0u8; 12];
        spki.extend_from_slice(&[0x42_u8; 32]);
        let body = B64.encode(&spki);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n");
        let decoded = decode_ed25519_spki_pem(&pem).expect("must decode");
        assert_eq!(decoded, vec![0x42_u8; 32]);
    }

    #[test]
    fn decode_spki_pem_bare_32() {
        let pk = vec![0xAA_u8; 32];
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(&pk)
        );
        let decoded = decode_ed25519_spki_pem(&pem).expect("must decode");
        assert_eq!(decoded, pk);
    }

    #[test]
    fn decode_spki_pem_wrong_length_returns_none() {
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode([0u8; 31])
        );
        assert!(decode_ed25519_spki_pem(&pem).is_none());

        let pem_long = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode([0u8; 100])
        );
        assert!(decode_ed25519_spki_pem(&pem_long).is_none());
    }

    #[test]
    fn decode_spki_pem_handles_multiline_body() {
        let mut spki = vec![0u8; 12];
        spki.extend_from_slice(&[0x7F_u8; 32]);
        let body = B64.encode(&spki);
        // Split into 16-char chunks like OpenSSL renders.
        let chunks: Vec<&str> = body
            .as_bytes()
            .chunks(16)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            chunks.join("\n")
        );
        let decoded = decode_ed25519_spki_pem(&pem).expect("must decode multiline PEM");
        assert_eq!(decoded, vec![0x7F_u8; 32]);
    }
}
