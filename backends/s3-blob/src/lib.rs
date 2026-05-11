//! S3-compatible blob backend for large receipt-evidence payloads.
//!
//! **Status: skeleton.** Implementation pending; see [`README.md`](../README.md).

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use async_trait::async_trait;
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

/// S3-backed implementation. Skeleton.
pub struct S3BlobStore {
    _client: aws_sdk_s3::Client,
    _bucket: String,
}

impl S3BlobStore {
    /// Build an S3 client and bind to a bucket.
    ///
    /// Uses `BehaviorVersion::latest()` explicitly so behavior changes in
    /// future AWS SDK versions are an opt-in upgrade rather than a silent
    /// drift. If you want frozen behavior, pin a specific BehaviorVersion
    /// (e.g. `BehaviorVersion::v2024_03_28()`) instead.
    pub async fn from_env(bucket: impl Into<String>) -> Result<Self> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let client = aws_sdk_s3::Client::new(&config);
        Ok(Self {
            _client: client,
            _bucket: bucket.into(),
        })
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, _address: &Hash, _bytes: &[u8]) -> Result<()> {
        // TODO: PutObject with key = base64(address.digest); ContentSHA256
        // header bound to the same digest for AWS verification.
        todo!("S3 put")
    }

    async fn get(&self, _address: &Hash) -> Result<Option<Vec<u8>>> {
        // TODO: GetObject; on success verify SHA-256(bytes) == address.digest.
        todo!("S3 get")
    }

    async fn exists(&self, _address: &Hash) -> Result<bool> {
        // TODO: HeadObject.
        todo!("S3 exists")
    }
}
