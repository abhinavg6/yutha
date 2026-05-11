//! Canonical-serialization helpers.
//!
//! Per [`/spec/README.md`](../../../spec/README.md) §5, the hash of a message
//! is computed over its canonical serialization: protobuf 3 deterministic
//! encoding with the `signature` field cleared, fields in ascending tag
//! order, no field tags with default-only payload, no preserved unknown
//! fields. Two implementations producing the same logical message MUST
//! produce identical bytes.
//!
//! This module provides the helpers that callers wire in once they have
//! prost-generated message types. Until proto bindings land in Phase 1
//! reference implementation, this module is shape-only — the trait is here,
//! the implementation lands when prost arrives.

use crate::error::{CryptoError, Result};
use yutha_core::Hash;

/// A type that can be canonically serialized.
///
/// Implementors are typically prost-generated message types; the trait wraps
/// `prost::Message::encode_to_vec` plus the rules from
/// [`/spec/README.md`](../../../spec/README.md) §5 (clear signature, sort by
/// tag, omit defaults, no unknown fields preserved).
pub trait Canonical {
    /// Produce the canonical byte sequence for hashing.
    ///
    /// Implementors MUST clear any signature field before serializing and
    /// MUST use deterministic protobuf encoding.
    fn canonical_bytes(&self) -> Result<Vec<u8>>;
}

/// Compute the SHA-256 content-address of a [`Canonical`] value.
///
/// This is the building block for content-addressing across passport,
/// envelope, receipt, and capability. Equivalent to `sha256(value.canonical_bytes())`.
pub fn content_address<T: Canonical>(value: &T) -> Result<Hash> {
    let bytes = value.canonical_bytes()?;
    Ok(crate::hash::sha256(&bytes))
}

/// Verify that `value`'s recomputed content-address matches `expected`.
/// Returns Ok if they match, [`CryptoError::VerificationFailed`] otherwise.
pub fn verify_content_address<T: Canonical>(value: &T, expected: &Hash) -> Result<()> {
    let computed = content_address(value)?;
    if &computed == expected {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test-only canonical type. Not representative of real wire format —
    /// just exercises the trait's contract.
    struct ToyMessage {
        bytes: Vec<u8>,
    }

    impl Canonical for ToyMessage {
        fn canonical_bytes(&self) -> Result<Vec<u8>> {
            Ok(self.bytes.clone())
        }
    }

    #[test]
    fn content_address_is_sha256_of_bytes() {
        let msg = ToyMessage {
            bytes: b"hello".to_vec(),
        };
        let addr = content_address(&msg).unwrap();
        let direct = crate::hash::sha256(b"hello");
        assert_eq!(addr, direct);
    }

    #[test]
    fn verify_content_address_passes_on_match() {
        let msg = ToyMessage {
            bytes: b"hello".to_vec(),
        };
        let addr = content_address(&msg).unwrap();
        assert!(verify_content_address(&msg, &addr).is_ok());
    }

    #[test]
    fn verify_content_address_fails_on_mismatch() {
        let msg = ToyMessage {
            bytes: b"hello".to_vec(),
        };
        let other = crate::hash::sha256(b"goodbye");
        assert!(matches!(
            verify_content_address(&msg, &other),
            Err(CryptoError::VerificationFailed)
        ));
    }
}
