//! [`Hash`] — algorithm-tagged content-address.
//!
//! Mirrors `Hash` and `HashAlgorithm` from
//! [`/spec/common.proto`](../../../spec/common.proto). Two implementations
//! that produce the same logical message MUST produce the same `Hash` bytes;
//! the canonical-serialization rules in [`/spec/README.md`](../../../spec/README.md)
//! §5 are what guarantee this.
//!
//! This type is the *value*. Computing a hash from data is in
//! [`yutha-crypto`](../../yutha_crypto/index.html); this crate just carries
//! the result around.

use crate::error::{CoreError, Result};

/// Algorithm tag for [`Hash`].
///
/// Only [`HashAlgorithm::Sha256`] is required at v1.0. [`HashAlgorithm::Blake3`]
/// is reserved for a v1.x minor addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HashAlgorithm {
    /// SHA-256. Required at v1.0.
    Sha256,
    /// BLAKE3. Reserved for v1.x; not required at v1.0.
    Blake3,
}

impl HashAlgorithm {
    /// Expected digest length in bytes for this algorithm.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Blake3 => 32,
        }
    }

    /// Parse from the proto wire-tag integer.
    pub fn from_wire(value: i32) -> Result<Self> {
        match value {
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Blake3),
            _ => Err(CoreError::UnknownEnumValue {
                context: "HashAlgorithm",
            }),
        }
    }

    /// Return the proto wire-tag integer.
    pub const fn to_wire(self) -> i32 {
        match self {
            Self::Sha256 => 1,
            Self::Blake3 => 2,
        }
    }
}

/// A content-address.
///
/// Construct via [`Hash::new`]; validate via [`Hash::validate`]. Equality is
/// over `(algorithm, digest)` — two hashes with different algorithms are
/// never equal, even if their digest bytes happen to coincide.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hash {
    /// Algorithm tag.
    pub algorithm: HashAlgorithm,
    /// Digest bytes. Length must match `algorithm.digest_len()`.
    pub digest: Vec<u8>,
}

impl Hash {
    /// Construct a hash, validating that `digest` matches the algorithm's
    /// expected length.
    pub fn new(algorithm: HashAlgorithm, digest: Vec<u8>) -> Result<Self> {
        if digest.len() != algorithm.digest_len() {
            return Err(CoreError::InvalidLength {
                expected: algorithm.digest_len(),
                actual: digest.len(),
            });
        }
        Ok(Self { algorithm, digest })
    }

    /// Re-validate length against algorithm. Use after deserialization from
    /// untrusted sources.
    pub fn validate(&self) -> Result<()> {
        if self.digest.len() != self.algorithm.digest_len() {
            return Err(CoreError::InvalidLength {
                expected: self.algorithm.digest_len(),
                actual: self.digest.len(),
            });
        }
        Ok(())
    }

    /// Hex string of the digest, prefixed with the algorithm name. Useful in
    /// logs; not authoritative.
    pub fn to_hex(&self) -> String {
        let mut s = match self.algorithm {
            HashAlgorithm::Sha256 => String::from("sha256:"),
            HashAlgorithm::Blake3 => String::from("blake3:"),
        };
        for byte in &self.digest {
            use std::fmt::Write;
            let _ = write!(s, "{byte:02x}");
        }
        s
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_requires_32_bytes() {
        assert!(Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).is_ok());
        assert!(Hash::new(HashAlgorithm::Sha256, vec![0u8; 31]).is_err());
        assert!(Hash::new(HashAlgorithm::Sha256, vec![0u8; 33]).is_err());
    }

    #[test]
    fn algorithm_tag_round_trips() {
        assert_eq!(
            HashAlgorithm::from_wire(HashAlgorithm::Sha256.to_wire()).unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            HashAlgorithm::from_wire(HashAlgorithm::Blake3.to_wire()).unwrap(),
            HashAlgorithm::Blake3
        );
    }

    #[test]
    fn unknown_algorithm_value_is_error() {
        assert!(HashAlgorithm::from_wire(0).is_err());
        assert!(HashAlgorithm::from_wire(99).is_err());
    }

    #[test]
    fn different_algorithms_never_equal() {
        let sha = Hash::new(HashAlgorithm::Sha256, vec![1u8; 32]).unwrap();
        let blake = Hash::new(HashAlgorithm::Blake3, vec![1u8; 32]).unwrap();
        assert_ne!(sha, blake);
    }

    #[test]
    fn hex_includes_algorithm_prefix() {
        let h = Hash::new(HashAlgorithm::Sha256, vec![0xab; 32]).unwrap();
        let hex = h.to_hex();
        assert!(hex.starts_with("sha256:"));
        assert_eq!(hex.len(), "sha256:".len() + 64);
    }
}
