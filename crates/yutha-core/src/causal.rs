//! [`CausalRef`] — predecessor pointers that emit the causal DAG.
//!
//! Mirrors `CausalRef` from
//! [`/spec/common.proto`](../../../spec/common.proto). Per build-plan §4.8:
//! "the DAG is emitted, not reconstructed." Every envelope and every receipt
//! carries predecessors; the conformance suite verifies they are preserved
//! end-to-end across registry, transport, and store boundaries.

use crate::hash::Hash;

/// Causal reference — a list of predecessor receipts (by content-address)
/// that the bearing message or receipt depends on.
///
/// Empty only for the genesis message of a chain. The conformance suite tests
/// that this set is preserved across transport hops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CausalRef {
    /// Predecessor hashes. Order is preserved on the wire but is not
    /// semantically meaningful — predecessors form a set, not a list.
    pub predecessors: Vec<Hash>,
}

impl CausalRef {
    /// Construct an empty (genesis) causal reference.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of predecessors.
    pub fn len(&self) -> usize {
        self.predecessors.len()
    }

    /// Whether the causal ref is the genesis (no predecessors).
    pub fn is_empty(&self) -> bool {
        self.predecessors.is_empty()
    }

    /// Iterator over predecessor hashes.
    pub fn iter(&self) -> std::slice::Iter<'_, Hash> {
        self.predecessors.iter()
    }
}

/// Build a [`CausalRef`] from any iterator of [`Hash`] values.
///
/// Implements the standard [`FromIterator`] trait so callers can use
/// `iter.collect::<CausalRef>()` ergonomics; the inherent
/// `CausalRef::from_iter([...])` form continues to work via the trait method.
impl FromIterator<Hash> for CausalRef {
    fn from_iter<I: IntoIterator<Item = Hash>>(iter: I) -> Self {
        Self {
            predecessors: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HashAlgorithm;

    fn hash_of(byte: u8) -> Hash {
        Hash::new(HashAlgorithm::Sha256, vec![byte; 32]).unwrap()
    }

    #[test]
    fn empty_is_genesis() {
        let c = CausalRef::empty();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn from_iter_preserves_order_on_wire() {
        let h1 = hash_of(1);
        let h2 = hash_of(2);
        let h3 = hash_of(3);
        let c = CausalRef::from_iter([h1.clone(), h2.clone(), h3.clone()]);
        let collected: Vec<_> = c.iter().cloned().collect();
        assert_eq!(collected, vec![h1, h2, h3]);
    }
}
