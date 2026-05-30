//! The [`Signer`] trait — the single Ed25519 signing abstraction in Yutha.

use crate::error::SignerError;
use async_trait::async_trait;
use std::fmt::Debug;
use yutha_core::{PublicKey, Signature};

/// A handle to an Ed25519 signing capability.
///
/// Every Ed25519 signature in the Yutha substrate is produced through this
/// trait. Implementations may hold the private key in process memory
/// (`InProcessSigner`, the zero-dependency default), or hold only a handle
/// to an external custody backend like a cloud KMS or HashiCorp Vault.
///
/// # Invariants implementations MUST uphold
///
/// 1. **No raw-key export.** Implementations MUST NOT expose the raw private
///    key bytes via any method, trait, or downcast. The trait surface
///    (`public_key` + `sign_message`) is the only path; KMS-backed
///    implementations *cannot* expose private bytes because they don't have
///    them, and the in-process implementation *will not* because the trait
///    forbids it.
///
/// 2. **Ed25519 only.** The returned signature MUST verify under
///    [`Signer::public_key`] per [RFC 8032]. Implementations wrapping
///    KMS keys MUST wrap Ed25519 keys; algorithm-agnostic signing is a
///    future RFC, not a v1 deliverable.
///
/// 3. **Public key cached at construction.** [`Signer::public_key`] MUST be
///    sync and infallible. Implementations that need a network call to
///    discover the public key (e.g., cloud KMS) MUST perform that fetch
///    at construction time and cache the result.
///
/// 4. **Concurrent-safe.** Implementations MUST be safe to call concurrently
///    (the `Send + Sync` bound is part of the contract).
///
/// [RFC 8032]: https://datatracker.ietf.org/doc/html/rfc8032
///
/// # Example
///
/// ```no_run
/// use yutha_signer::{InProcessSigner, Signer};
///
/// # async fn example() {
/// let signer: Box<dyn Signer> = Box::new(InProcessSigner::generate());
/// let pk = signer.public_key();
/// let sig = signer.sign_message(b"hello").await.unwrap();
/// // `sig` verifies under `pk` per RFC 8032.
/// # }
/// ```
#[async_trait]
pub trait Signer: Send + Sync + Debug {
    /// Return the Ed25519 public key this signer signs for.
    ///
    /// Implementations MUST cache this value at construction. This method
    /// MUST NOT make network calls or block.
    fn public_key(&self) -> PublicKey;

    /// Sign the given canonical bytes.
    ///
    /// Implementations MUST return a signature that verifies under
    /// [`Signer::public_key`] per RFC 8032. Implementations MAY:
    ///   - cache nothing (every call hits the backend);
    ///   - retry transient backend failures internally;
    ///   - emit telemetry / audit-log entries to their backend;
    ///   - rate-limit calls to protect the backend.
    ///
    /// Implementations MUST NOT:
    ///   - return a signature produced by a different key than
    ///     [`Signer::public_key`] reports;
    ///   - mutate the input bytes;
    ///   - return until the signing operation has either succeeded or
    ///     failed (no fire-and-forget).
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;
}
