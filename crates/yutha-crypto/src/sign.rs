//! Ed25519 signing and verification.
//!
//! Wraps `ed25519-dalek`. Returns the value types from `yutha-core`.

use crate::error::{CryptoError, Result};
use crate::hash::fingerprint_public_key;
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey as DalekSigningKey, Verifier};
use rand_core::{OsRng, RngCore};
use yutha_core::{PublicKey, Signature, SignatureAlgorithm};

/// A signing keypair (private + public).
///
/// The private key bytes never leave this struct. To persist or transfer,
/// callers must explicitly use [`SigningKey::to_bytes`] and accept the
/// security responsibility.
pub struct SigningKey {
    inner: DalekSigningKey,
}

impl SigningKey {
    /// Create the keypair from raw 32-byte secret material.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self {
            inner: DalekSigningKey::from_bytes(secret),
        }
    }

    /// Export the secret bytes. Use sparingly; treat as a credential.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Public key derived from this signing key, in the `yutha-core` shape.
    pub fn public(&self) -> PublicKey {
        let bytes = self.inner.verifying_key().to_bytes().to_vec();
        // Lengths come straight from ed25519; PublicKey::new revalidates.
        PublicKey::new(SignatureAlgorithm::Ed25519, bytes).expect("ed25519 public key is 32 bytes")
    }

    /// SHA-256 fingerprint of the public key. 32 bytes.
    pub fn public_fingerprint(&self) -> Vec<u8> {
        fingerprint_public_key(&self.inner.verifying_key().to_bytes())
    }

    /// Sign `message` and return the resulting [`Signature`] with key
    /// fingerprint populated.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        let sig = self.inner.sign(message);
        let fingerprint = self.public_fingerprint();
        Signature::new(
            SignatureAlgorithm::Ed25519,
            sig.to_bytes().to_vec(),
            fingerprint,
        )
        .expect("ed25519 signature is 64 bytes; fingerprint is 32 bytes")
    }
}

/// A verification key — the public-key half.
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl VerifyingKey {
    /// Build a verifying key from `yutha-core` value bytes. Returns error if
    /// the algorithm is not Ed25519 or the bytes are not a valid Ed25519
    /// public key.
    pub fn from_public_key(pk: &PublicKey) -> Result<Self> {
        if pk.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(CryptoError::InvalidKey(format!(
                "expected Ed25519, got {:?}",
                pk.algorithm
            )));
        }
        let arr: [u8; 32] =
            pk.value.as_slice().try_into().map_err(|_| {
                CryptoError::InvalidKey("ed25519 public key must be 32 bytes".into())
            })?;
        let inner = ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| CryptoError::InvalidKey(format!("invalid ed25519 public key: {e}")))?;
        Ok(Self { inner })
    }

    /// Verify `signature` over `message`. Returns Ok on success;
    /// [`CryptoError::VerificationFailed`] on mismatch.
    pub fn verify_message(&self, message: &[u8], signature: &Signature) -> Result<()> {
        if signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(CryptoError::InvalidSignature(format!(
                "expected Ed25519, got {:?}",
                signature.algorithm
            )));
        }
        let arr: [u8; 64] =
            signature.value.as_slice().try_into().map_err(|_| {
                CryptoError::InvalidSignature("ed25519 sig must be 64 bytes".into())
            })?;
        let dalek_sig = DalekSignature::from_bytes(&arr);
        self.inner
            .verify(message, &dalek_sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

/// Generate a fresh Ed25519 keypair. Uses the operating system's CSPRNG
/// (`OsRng`).
pub fn generate_keypair() -> SigningKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

/// Convenience: sign `message` with `signing_key`. Equivalent to
/// `signing_key.sign_message(message)`.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign_message(message)
}

/// Convenience: verify `signature` over `message` against `public_key`.
/// Builds a [`VerifyingKey`] internally; for repeated verification against
/// the same key, construct the [`VerifyingKey`] once and reuse it.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    let vk = VerifyingKey::from_public_key(public_key)?;
    vk.verify_message(message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_round_trips() {
        let key = generate_keypair();
        let pk = key.public();
        let sig = sign(&key, b"hello");
        assert!(verify(&pk, b"hello", &sig).is_ok());
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let key = generate_keypair();
        let pk = key.public();
        let sig = sign(&key, b"hello");
        assert!(matches!(
            verify(&pk, b"goodbye", &sig),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let key = generate_keypair();
        let pk = key.public();
        let mut sig = sign(&key, b"hello");
        // Flip a byte.
        sig.value[0] ^= 0xff;
        assert!(matches!(
            verify(&pk, b"hello", &sig),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_fails_on_wrong_key() {
        let key1 = generate_keypair();
        let key2 = generate_keypair();
        let sig = sign(&key1, b"hello");
        assert!(matches!(
            verify(&key2.public(), b"hello", &sig),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn signature_carries_correct_fingerprint() {
        let key = generate_keypair();
        let sig = sign(&key, b"hello");
        assert_eq!(sig.key_fingerprint, key.public_fingerprint());
    }

    #[test]
    fn fingerprint_matches_sha256_of_public_key_bytes() {
        let key = generate_keypair();
        let pk = key.public();
        assert_eq!(key.public_fingerprint(), fingerprint_public_key(&pk.value));
    }
}
