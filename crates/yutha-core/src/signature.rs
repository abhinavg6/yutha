//! [`Signature`] and [`PublicKey`] — algorithm-tagged crypto value containers.
//!
//! These are *value types*. Computing signatures and verifying them lives in
//! [`yutha-crypto`](../../yutha_crypto/index.html); this crate just carries
//! the bytes around with the right shape.
//!
//! Mirrors `Signature`, `PublicKey`, and `SignatureAlgorithm` from
//! [`/spec/common.proto`](../../../spec/common.proto).

use crate::error::{CoreError, Result};

/// Signature algorithm tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignatureAlgorithm {
    /// Ed25519. Required at v1.0.
    Ed25519,
    /// Reserved for a future post-quantum scheme.
    ReservedPq,
}

impl SignatureAlgorithm {
    /// Expected signature length in bytes for this algorithm.
    pub const fn signature_len(self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::ReservedPq => {
                // Unknown until the scheme is chosen. Using 0 here forces
                // any caller that touches ReservedPq to handle it explicitly.
                0
            }
        }
    }

    /// Expected public-key length in bytes.
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::ReservedPq => 0,
        }
    }

    /// Parse from the proto wire-tag integer.
    pub fn from_wire(value: i32) -> Result<Self> {
        match value {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::ReservedPq),
            _ => Err(CoreError::UnknownEnumValue {
                context: "SignatureAlgorithm",
            }),
        }
    }

    /// Return the proto wire-tag integer.
    pub const fn to_wire(self) -> i32 {
        match self {
            Self::Ed25519 => 1,
            Self::ReservedPq => 2,
        }
    }
}

/// A signature value. Carries the algorithm, the bytes, and a fingerprint of
/// the producing public key (SHA-256 of the public-key bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature {
    /// Algorithm tag.
    pub algorithm: SignatureAlgorithm,
    /// Signature bytes. Length must match `algorithm.signature_len()`.
    pub value: Vec<u8>,
    /// SHA-256 fingerprint of the public key bytes. 32 bytes.
    pub key_fingerprint: Vec<u8>,
}

impl Signature {
    /// Construct a signature, validating field lengths.
    pub fn new(
        algorithm: SignatureAlgorithm,
        value: Vec<u8>,
        key_fingerprint: Vec<u8>,
    ) -> Result<Self> {
        if algorithm == SignatureAlgorithm::ReservedPq {
            return Err(CoreError::Validation(
                "ReservedPq signature algorithm has no v1.0 binding".into(),
            ));
        }
        if value.len() != algorithm.signature_len() {
            return Err(CoreError::InvalidLength {
                expected: algorithm.signature_len(),
                actual: value.len(),
            });
        }
        if key_fingerprint.len() != 32 {
            return Err(CoreError::InvalidLength {
                expected: 32,
                actual: key_fingerprint.len(),
            });
        }
        Ok(Self {
            algorithm,
            value,
            key_fingerprint,
        })
    }
}

/// A public key value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey {
    /// Algorithm tag.
    pub algorithm: SignatureAlgorithm,
    /// Public-key bytes. Length must match `algorithm.public_key_len()`.
    pub value: Vec<u8>,
}

impl PublicKey {
    /// Construct a public key, validating length.
    pub fn new(algorithm: SignatureAlgorithm, value: Vec<u8>) -> Result<Self> {
        if algorithm == SignatureAlgorithm::ReservedPq {
            return Err(CoreError::Validation(
                "ReservedPq signature algorithm has no v1.0 binding".into(),
            ));
        }
        if value.len() != algorithm.public_key_len() {
            return Err(CoreError::InvalidLength {
                expected: algorithm.public_key_len(),
                actual: value.len(),
            });
        }
        Ok(Self { algorithm, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_signature_requires_64_bytes() {
        let sig =
            Signature::new(SignatureAlgorithm::Ed25519, vec![0u8; 64], vec![0u8; 32]).unwrap();
        assert_eq!(sig.value.len(), 64);

        assert!(Signature::new(SignatureAlgorithm::Ed25519, vec![0u8; 63], vec![0u8; 32]).is_err());
    }

    #[test]
    fn ed25519_public_key_requires_32_bytes() {
        let pk = PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32]).unwrap();
        assert_eq!(pk.value.len(), 32);
        assert!(PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 31]).is_err());
    }

    #[test]
    fn reserved_pq_is_rejected_at_v1() {
        assert!(Signature::new(SignatureAlgorithm::ReservedPq, vec![], vec![0u8; 32]).is_err());
        assert!(PublicKey::new(SignatureAlgorithm::ReservedPq, vec![]).is_err());
    }

    #[test]
    fn signature_requires_32_byte_fingerprint() {
        assert!(Signature::new(SignatureAlgorithm::Ed25519, vec![0u8; 64], vec![0u8; 31]).is_err());
        assert!(Signature::new(SignatureAlgorithm::Ed25519, vec![0u8; 64], vec![0u8; 33]).is_err());
    }
}
