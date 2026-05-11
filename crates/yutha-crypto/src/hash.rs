//! Hash primitives.
//!
//! SHA-256 is the v1.0 required algorithm. BLAKE3 is reserved for v1.x and
//! will land via a future RFC.

use sha2::{Digest, Sha256};
use yutha_core::{Hash, HashAlgorithm};

/// Compute SHA-256 over `bytes` and return a [`Hash`] tagged
/// [`HashAlgorithm::Sha256`].
pub fn sha256(bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize().to_vec();
    // SAFETY: SHA-256 always produces exactly 32 bytes; Hash::new validates.
    Hash::new(HashAlgorithm::Sha256, digest).expect("sha256 always produces 32 bytes")
}

/// Compute the public-key fingerprint: SHA-256 of the public-key bytes.
///
/// Used as `Signature::key_fingerprint` and as the lookup key in passport
/// stores. 32 bytes.
pub fn fingerprint_public_key(public_key_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of empty input.
        let h = sha256(b"");
        assert_eq!(h.algorithm, HashAlgorithm::Sha256);
        assert_eq!(
            h.to_hex(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc_known_vector() {
        let h = sha256(b"abc");
        assert_eq!(
            h.to_hex(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fingerprint_is_32_bytes() {
        let fp = fingerprint_public_key(&[0u8; 32]);
        assert_eq!(fp.len(), 32);
    }

    #[test]
    fn distinct_inputs_distinct_hashes() {
        let a = sha256(b"hello");
        let b = sha256(b"world");
        assert_ne!(a, b);
    }
}
