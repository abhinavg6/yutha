//! S3-compatible blob backend for large receipt-evidence payloads.
//!
//! **Status: implemented.** See [`README.md`](../README.md).

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use async_trait::async_trait;
use sha2::Digest as _;
use thiserror::Error;
use yutha_core::Hash;

/// A simple blob-store interface keyed by content-address.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Put a blob keyed by its content-address. Returns the address back.
    /// Idempotent: putting the same content twice is a no-op.
    async fn put(&self, address: &Hash, bytes: &[u8]) -> Result<()>;

    /// Fetch a blob by content-address. Returns None if not found.
    async fn get(&self, address: &Hash) -> Result<Option<Vec<u8>>>;

    /// Check existence without transferring the bytes.
    async fn exists(&self, address: &Hash) -> Result<bool>;
}

/// Errors from blob operations.
#[derive(Debug, Error)]
pub enum BlobError {
    /// Backend I/O failure.
    #[error("backend error: {0}")]
    Backend(String),

    /// Content-address mismatch on read (bytes don't hash to the claimed address).
    #[error("content-address mismatch: blob bytes do not match key {0}")]
    AddressMismatch(Hash),
}

/// Result type bound to [`BlobError`].
pub type Result<T> = std::result::Result<T, BlobError>;

/// S3-backed implementation of [`BlobStore`].
///
/// Keys are hex-encoded SHA-256 digests. On [`get`][BlobStore::get] the
/// returned bytes are verified against the content-address before returning,
/// so any corruption or key-collision is caught at the read boundary.
pub struct S3BlobStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3BlobStore {
    /// Build an S3 client from the environment and bind to a bucket.
    ///
    /// Uses `BehaviorVersion::latest()` explicitly so behavior changes in
    /// future AWS SDK versions are an opt-in upgrade rather than a silent
    /// drift. If you want frozen behavior, pin a specific BehaviorVersion
    /// (e.g. `BehaviorVersion::v2024_03_28()`) instead.
    pub async fn from_env(bucket: impl Into<String>) -> Result<Self> {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        // Force path-style when a custom endpoint is set (MinIO, Localstack, R2, etc.).
        // Virtual-hosted-style only works reliably against AWS S3 itself.
        let force_path_style = std::env::var("AWS_ENDPOINT_URL").is_ok();
        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(force_path_style)
            .build();
        let client = aws_sdk_s3::Client::from_conf(s3_config);
        Ok(Self {
            client,
            bucket: bucket.into(),
        })
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, address: &Hash, bytes: &[u8]) -> Result<()> {
        let key = hex::encode(&address.digest);
        let body = aws_sdk_s3::primitives::ByteStream::from(bytes.to_vec());
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .send()
            .await
            .map_err(|e| BlobError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, address: &Hash) -> Result<Option<Vec<u8>>> {
        let key = hex::encode(&address.digest);
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                if let aws_sdk_s3::error::SdkError::ServiceError(ref svc) = e {
                    if svc.err().is_no_such_key() {
                        return Ok(None);
                    }
                }
                return Err(BlobError::Backend(e.to_string()));
            }
        };

        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| BlobError::Backend(e.to_string()))?
            .into_bytes()
            .to_vec();

        // Verify content-address integrity before returning to the caller.
        let computed: Vec<u8> = sha2::Sha256::digest(&bytes).to_vec();
        if computed != address.digest {
            return Err(BlobError::AddressMismatch(address.clone()));
        }

        Ok(Some(bytes))
    }

    async fn exists(&self, address: &Hash) -> Result<bool> {
        let key = hex::encode(&address.digest);
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if let aws_sdk_s3::error::SdkError::ServiceError(ref svc) = e {
                    if svc.err().is_not_found() {
                        return Ok(false);
                    }
                }
                Err(BlobError::Backend(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_core::{Hash, HashAlgorithm};

    fn sha256_hash(digest: [u8; 32]) -> Hash {
        Hash::new(HashAlgorithm::Sha256, digest.to_vec()).unwrap()
    }

    #[test]
    fn key_encoding_is_hex_of_digest() {
        let digest = [0xab_u8; 32];
        let hash = sha256_hash(digest);
        let key = hex::encode(&hash.digest);
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(&key[..4], "abab");
    }

    #[test]
    fn content_address_mismatch_detected() {
        // Simulate what `get` does after fetching bytes from S3.
        let real_bytes = b"hello yutha";
        let correct_digest: Vec<u8> = sha2::Sha256::digest(real_bytes).to_vec();

        // A hash that claims a different digest.
        let wrong_digest = vec![0xff_u8; 32];
        let wrong_hash = sha256_hash(wrong_digest.try_into().unwrap());

        let computed: Vec<u8> = sha2::Sha256::digest(real_bytes).to_vec();
        // Mismatch should be detected.
        assert_ne!(computed, wrong_hash.digest);

        // Correct hash should match.
        let correct_hash = Hash::new(HashAlgorithm::Sha256, correct_digest).unwrap();
        let computed2: Vec<u8> = sha2::Sha256::digest(real_bytes).to_vec();
        assert_eq!(computed2, correct_hash.digest);
    }

    #[test]
    fn blob_error_display() {
        let backend_err = BlobError::Backend("connection refused".to_string());
        assert!(backend_err.to_string().contains("connection refused"));

        let hash = sha256_hash([0x00; 32]);
        let mismatch_err = BlobError::AddressMismatch(hash);
        assert!(mismatch_err
            .to_string()
            .contains("content-address mismatch"));
    }
}
