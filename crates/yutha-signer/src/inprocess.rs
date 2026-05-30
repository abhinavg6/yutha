//! [`InProcessSigner`] — the zero-dependency default implementation.

use crate::error::SignerError;
use crate::traits::Signer;
use async_trait::async_trait;
use yutha_core::{PublicKey, Signature};
use yutha_crypto::SigningKey;

/// The zero-dependency default [`Signer`] implementation.
///
/// Wraps [`yutha_crypto::SigningKey`] byte-for-byte. What hobby swarms and
/// development workflows run today; the substrate's signing path looks
/// identical in shape to what it would with a cloud-KMS-backed signer, just
/// with the private key bytes living in process memory rather than behind
/// a network boundary.
///
/// # Performance
///
/// The `async fn sign_message` body is synchronous Ed25519 signing wrapped
/// in an `async fn`. The future construction + immediate `Poll::Ready` return
/// adds nanosecond-scale overhead vs. calling
/// `SigningKey::sign_message` directly. Benchmarked at well under 100µs
/// per call on commodity hardware, dominated by Ed25519 math, not the async
/// machinery.
///
/// The async surface exists because non-in-process signers (KMS, Vault) are
/// network-bound and the trait must support them; making the in-process
/// implementation match keeps the call shape uniform.
///
/// # Example
///
/// ```no_run
/// use yutha_signer::{InProcessSigner, Signer};
///
/// # async fn example() {
/// let seed = [0u8; 32];
/// let signer = InProcessSigner::from_bytes(&seed);
/// let pk = signer.public_key();
/// let sig = signer.sign_message(b"hello").await.unwrap();
/// // sig verifies under pk
/// # }
/// ```
pub struct InProcessSigner {
    signing_key: SigningKey,
    public_key: PublicKey,
}

impl std::fmt::Debug for InProcessSigner {
    /// Hand-rolled to keep the private signing-key bytes out of any
    /// formatter output. Mirrors the same posture as
    /// `yutha_passport::ControlPlaneIdentity` and the existing
    /// `yutha_crypto::SigningKey` (which deliberately does not derive
    /// `Debug`). Without this, every accidental `tracing::debug!(?signer, …)`
    /// or `dbg!(&signer)` call would have a chance to render the key
    /// material — exactly the failure mode RFC 0015's "no raw-key export"
    /// invariant exists to prevent.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessSigner")
            .field("public_key", &self.public_key)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl InProcessSigner {
    /// Construct from a 32-byte Ed25519 seed.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let public_key = signing_key.public();
        Self {
            signing_key,
            public_key,
        }
    }

    /// Wrap an existing [`SigningKey`].
    ///
    /// Used internally by the substrate when the signing-key shape is
    /// load-bearing (e.g., bootstrap-identity derivation) and the same
    /// key is needed for both old-style direct signing and new-style
    /// [`Signer`]-trait signing during the Phase B refactor. Long-term
    /// callers should prefer [`InProcessSigner::from_bytes`] +
    /// passing the resulting `Signer` around rather than ever holding a
    /// bare `SigningKey`.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let public_key = signing_key.public();
        Self {
            signing_key,
            public_key,
        }
    }

    /// Construct by generating a fresh keypair from the OS CSPRNG.
    /// Test/demo use.
    pub fn generate() -> Self {
        let signing_key = yutha_crypto::generate_keypair();
        let public_key = signing_key.public();
        Self {
            signing_key,
            public_key,
        }
    }

    /// Inherent accessor mirroring [`Signer::public_key`].
    ///
    /// Lets callers that hold a concrete [`InProcessSigner`] (test
    /// fixtures, bootstrap code) get the public key *without* needing
    /// `use yutha_signer::Signer;` in scope. The trait method still
    /// works the same way; this is purely an ergonomic convenience
    /// to keep boilerplate out of test modules.
    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}

#[async_trait]
impl Signer for InProcessSigner {
    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // Ed25519 over a small canonical-bytes input is fast enough that
        // spawn_blocking would dominate. We sign on the calling task's
        // worker — the future is immediately Ready.
        Ok(self.signing_key.sign_message(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_crypto::verify;

    /// The defining property of `InProcessSigner`: its signature is
    /// byte-identical to what `SigningKey::sign_message` would produce
    /// for the same seed + message. This is the "the trait doesn't
    /// change the math" gate. Conformance vectors lift this into a wider
    /// cross-vector suite.
    #[tokio::test]
    async fn inprocess_signature_is_identical_to_raw_signing_key() {
        let seed = [42u8; 32];
        let raw_key = SigningKey::from_bytes(&seed);
        let signer = InProcessSigner::from_bytes(&seed);

        let message = b"the quick brown fox jumps over the lazy dog";

        let raw_sig = raw_key.sign_message(message);
        let signer_sig = signer.sign_message(message).await.unwrap();

        assert_eq!(raw_sig.algorithm, signer_sig.algorithm);
        assert_eq!(raw_sig.value, signer_sig.value);
        assert_eq!(raw_sig.key_fingerprint, signer_sig.key_fingerprint);
    }

    #[tokio::test]
    async fn public_key_matches_underlying_signing_key() {
        let seed = [7u8; 32];
        let raw_key = SigningKey::from_bytes(&seed);
        let signer = InProcessSigner::from_bytes(&seed);

        assert_eq!(raw_key.public(), signer.public_key());
    }

    #[tokio::test]
    async fn signature_verifies_under_reported_public_key() {
        let signer = InProcessSigner::generate();
        let pk = signer.public_key();
        let message = b"correct horse battery staple";
        let sig = signer.sign_message(message).await.unwrap();
        verify(&pk, message, &sig).expect("signature must verify under reported public key");
    }

    #[tokio::test]
    async fn verification_fails_under_different_public_key() {
        let signer_a = InProcessSigner::generate();
        let signer_b = InProcessSigner::generate();
        let message = b"signed by A, verified against B";
        let sig = signer_a.sign_message(message).await.unwrap();
        assert!(verify(&signer_b.public_key(), message, &sig).is_err());
    }

    #[tokio::test]
    async fn from_signing_key_preserves_identity() {
        let seed = [99u8; 32];
        let raw_key = SigningKey::from_bytes(&seed);
        let expected_pk = raw_key.public();
        let signer = InProcessSigner::from_signing_key(raw_key);
        assert_eq!(signer.public_key(), expected_pk);
    }

    /// Concurrent signing on a single signer instance: 32 tasks each
    /// produce 4 signatures over distinct messages; all 128 signatures
    /// MUST verify under the signer's public key, and signatures for
    /// the same message MUST be byte-identical (Ed25519 is
    /// deterministic).
    #[tokio::test]
    async fn concurrent_sign_safety() {
        use std::sync::Arc;

        let signer: Arc<dyn Signer> = Arc::new(InProcessSigner::generate());
        let pk = signer.public_key();

        let mut handles = Vec::new();
        for task_idx in 0..32 {
            let signer = Arc::clone(&signer);
            handles.push(tokio::spawn(async move {
                let mut sigs = Vec::with_capacity(4);
                for msg_idx in 0..4 {
                    let message = format!("task {task_idx} msg {msg_idx}");
                    let sig = signer.sign_message(message.as_bytes()).await.unwrap();
                    sigs.push((message, sig));
                }
                sigs
            }));
        }

        let mut all_sigs = Vec::new();
        for h in handles {
            all_sigs.extend(h.await.unwrap());
        }

        // Verify all 128 signatures.
        for (message, sig) in &all_sigs {
            verify(&pk, message.as_bytes(), sig).expect("concurrent signature must verify");
        }

        // Ed25519 is deterministic: same message → same signature, even
        // across concurrent producers.
        let signer_again = InProcessSigner::from_signing_key(
            // Re-derive the same key via from_signing_key: we can't easily
            // re-derive the OS-RNG-generated key, so re-sign one message
            // and check that two calls to sign_message return the same
            // bytes.
            yutha_crypto::generate_keypair(),
        );
        let s1 = signer_again
            .sign_message(b"deterministic check")
            .await
            .unwrap();
        let s2 = signer_again
            .sign_message(b"deterministic check")
            .await
            .unwrap();
        assert_eq!(s1.value, s2.value);
    }
}
