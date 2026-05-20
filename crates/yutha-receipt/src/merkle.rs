//! Deterministic SHA-256 Merkle tree construction for receipt batches.
//!
//! Implements the sorted-pair Merkle scheme specified in
//! [`/spec/verifiability/sui-anchoring.md`](../../../spec/verifiability/sui-anchoring.md)
//! §3. Sorted-pair hashing (`parent = sha256(min(a, b) || max(a, b))`)
//! means path verification needs no direction bits: a verifier just
//! repeatedly hashes `current` against each sibling in order.
//!
//! Leaves are receipts' content-addresses (i.e., the `receipt_id`
//! produced by [`yutha_crypto::content_address`]). The receipt's
//! canonical bytes are already SHA-256 hashed to form the id, so no
//! extra hashing round happens at the leaf level.
//!
//! ## Properties
//!
//! - **Determinism.** Same set of receipts produces the same root
//!   regardless of input order — the build sorts canonically before
//!   hashing.
//! - **Inclusion-only.** Paths prove a receipt was in the batch.
//!   They do NOT prove the receipt's position; sorted-pair hashing
//!   intentionally trades positional info for simpler wire format.
//! - **Odd-count handling.** A level with an odd number of nodes
//!   duplicates the last node before pairing (Bitcoin / Certificate
//!   Transparency convention). For sorted-pair this means
//!   `parent(a, a) = sha256(a.digest || a.digest)`.
//! - **1-leaf edge case.** The root equals the single leaf; the
//!   path is empty.

use yutha_core::{Hash, HashAlgorithm};
use yutha_crypto::canonical::content_address;
use yutha_crypto::sha256;

use crate::{Receipt, ReceiptError, Result};

/// A receipt sealed into a batch alongside its inclusion-proof path.
///
/// `path` is the list of sibling hashes from leaf to root (exclusive
/// of the leaf and root themselves). For a 1-leaf batch, `path` is
/// empty. Verifier reconstructs the root via [`verify_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafProof {
    /// The receipt's content-address (= the Merkle leaf).
    pub leaf: Hash,
    /// Sibling hashes, leaf→root order.
    pub path: Vec<Hash>,
}

/// Output of building a Merkle tree over a batch of receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleBatch {
    /// SHA-256 root hash over the canonically-sorted batch.
    pub root: Hash,
    /// Per-receipt inclusion proofs. Indices into `leaves` correspond
    /// 1:1 with this vector; `leaves[i]` plus `paths[i]` reconstructs
    /// `root`.
    pub leaves: Vec<LeafProof>,
}

/// Build a sorted-pair Merkle tree over `receipts`. Returns the root
/// plus per-receipt inclusion proofs.
///
/// Receipts are sorted by `(occurred_at.monotonic_ns ASC, receipt_id ASC)`
/// before hashing. Duplicate `receipt_id`s are rejected (an upstream
/// bug worth surfacing rather than silently merging).
///
/// Errors:
/// - [`ReceiptError::BatchInvalid`] for an empty batch.
/// - [`ReceiptError::BatchInvalid`] for a duplicate `receipt_id` within the batch.
/// - Errors from [`content_address`] surfacing through
///   [`ReceiptError::Crypto`] if a receipt fails canonical serialization.
pub fn build_merkle(receipts: &[Receipt]) -> Result<MerkleBatch> {
    if receipts.is_empty() {
        return Err(ReceiptError::BatchInvalid(
            "merkle batch must be non-empty".into(),
        ));
    }

    // Compute (sort_key, leaf_hash) pairs without cloning the full receipts
    // — the caller still owns them, we just need their content-addresses.
    let mut entries: Vec<(u64, Hash)> = receipts
        .iter()
        .map(|r| {
            let id = content_address(r).map_err(ReceiptError::Crypto)?;
            Ok::<_, ReceiptError>((r.occurred_at.monotonic_ns, id))
        })
        .collect::<Result<Vec<_>>>()?;

    // Canonical sort: (monotonic_ns ASC, receipt_id ASC).
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.digest.cmp(&b.1.digest)));

    // Reject duplicates. After sorting, any duplicate is adjacent.
    for pair in entries.windows(2) {
        if pair[0].1 == pair[1].1 {
            return Err(ReceiptError::BatchInvalid(format!(
                "duplicate receipt_id in batch: {}",
                hex(&pair[0].1.digest)
            )));
        }
    }

    let leaves: Vec<Hash> = entries.into_iter().map(|(_, h)| h).collect();

    // 1-leaf degenerate case: root == leaf, path is empty.
    if leaves.len() == 1 {
        let leaf = leaves.into_iter().next().expect("checked non-empty above");
        return Ok(MerkleBatch {
            root: leaf.clone(),
            leaves: vec![LeafProof {
                leaf,
                path: Vec::new(),
            }],
        });
    }

    // Build the tree level by level, tracking each original leaf's
    // sibling at every level.
    //
    // Invariants during the loop:
    //   - `current_level` holds the nodes at the current tree level.
    //   - `leaf_positions[i]` is the index within `current_level` of
    //     the subtree containing the original leaf at index i.
    //   - `paths[i]` accumulates the sibling hashes for leaf i.
    let n = leaves.len();
    let mut paths: Vec<Vec<Hash>> = vec![Vec::new(); n];
    let mut leaf_positions: Vec<usize> = (0..n).collect();
    let mut current_level: Vec<Hash> = leaves.clone();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut chunk_start = 0;
        while chunk_start < current_level.len() {
            let left = current_level[chunk_start].clone();
            let right = if chunk_start + 1 < current_level.len() {
                current_level[chunk_start + 1].clone()
            } else {
                // Odd-count level: duplicate the last node.
                left.clone()
            };

            // For every original leaf whose subtree maps through this
            // pair at this level, record the sibling.
            for (leaf_idx, pos) in leaf_positions.iter().enumerate() {
                if *pos == chunk_start {
                    paths[leaf_idx].push(right.clone());
                } else if *pos == chunk_start + 1 {
                    paths[leaf_idx].push(left.clone());
                }
            }

            next_level.push(sorted_pair_hash(&left, &right));
            chunk_start += 2;
        }

        // Move each leaf's position up one level: pair (2k, 2k+1) collapses to k.
        for pos in leaf_positions.iter_mut() {
            *pos /= 2;
        }
        current_level = next_level;
    }

    let root = current_level
        .into_iter()
        .next()
        .expect("tree must collapse to a single root");

    let leaf_proofs = leaves
        .into_iter()
        .zip(paths)
        .map(|(leaf, path)| LeafProof { leaf, path })
        .collect();

    Ok(MerkleBatch {
        root,
        leaves: leaf_proofs,
    })
}

/// Verify a Merkle inclusion path. Returns true iff `path` reconstructs
/// `expected_root` from `leaf` under the sorted-pair convention.
///
/// Use this from external verifiers that hold a receipt + path and want
/// to confirm against the on-chain or on-disk root without trusting the
/// store that produced the path.
pub fn verify_path(leaf: &Hash, path: &[Hash], expected_root: &Hash) -> bool {
    let mut current = leaf.clone();
    for sibling in path {
        current = sorted_pair_hash(&current, sibling);
    }
    &current == expected_root
}

/// Sorted-pair internal-node hash: `sha256(min(a, b) || max(a, b))`.
///
/// Visible at module level so external verifiers and the canonical
/// preimage test-vector generator can re-use the exact byte ordering.
pub fn sorted_pair_hash(a: &Hash, b: &Hash) -> Hash {
    // Reject mismatched algorithms early — sorted-pair across
    // algorithms doesn't make sense and would silently produce a
    // wrong hash. v1 is SHA-256 only; defensive check is cheap.
    debug_assert_eq!(a.algorithm, HashAlgorithm::Sha256);
    debug_assert_eq!(b.algorithm, HashAlgorithm::Sha256);

    let mut bytes = Vec::with_capacity(64);
    if a.digest <= b.digest {
        bytes.extend_from_slice(&a.digest);
        bytes.extend_from_slice(&b.digest);
    } else {
        bytes.extend_from_slice(&b.digest);
        bytes.extend_from_slice(&a.digest);
    }
    sha256(&bytes)
}

/// Compact hex for error messages. Not exposed publicly.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use crate::receipt::Receipt;
    use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};

    fn fixed_swarm() -> SwarmId {
        SwarmId::from_bytes(&[1u8; 16]).expect("16 bytes")
    }

    fn fixed_agent(seed: u8) -> AgentId {
        let mut bytes = [0u8; 16];
        bytes[0] = seed;
        AgentId::from_bytes(&bytes).expect("16 bytes")
    }

    /// Build a fixture receipt whose only inputs varying between
    /// fixtures are `monotonic_ns` and a per-receipt seed (folded into
    /// the actor id) — this makes content-addresses distinct and
    /// reproducible.
    fn fixture(monotonic_ns: u64, seed: u8) -> Receipt {
        Receipt::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(fixed_swarm())
            .actor(fixed_agent(seed))
            .action_kind("envelope.send")
            .causal(CausalRef::default())
            .evidence(Evidence::new("test_key", "test/type", vec![seed; 4]))
            .constitution_version("1.0.0")
            .occurred_at(
                Timestamp::new(
                    format!("2026-05-{:02}T00:00:00Z", (seed % 28) + 1),
                    monotonic_ns,
                )
                .unwrap(),
            )
            .build()
            .expect("fixture is valid")
    }

    #[test]
    fn empty_batch_rejected() {
        let err = build_merkle(&[]).expect_err("empty batch must error");
        match err {
            ReceiptError::BatchInvalid(msg) => assert!(msg.contains("non-empty"), "got: {msg}"),
            other => panic!("expected BatchInvalid, got {other:?}"),
        }
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let r = fixture(100, 1);
        let id = content_address(&r).unwrap();
        let batch = build_merkle(&[r]).unwrap();
        assert_eq!(batch.root, id);
        assert_eq!(batch.leaves.len(), 1);
        assert!(batch.leaves[0].path.is_empty());
        assert_eq!(batch.leaves[0].leaf, id);
    }

    #[test]
    fn two_leaf_path_verifies() {
        let r0 = fixture(100, 1);
        let r1 = fixture(200, 2);
        let batch = build_merkle(&[r0, r1]).unwrap();
        assert_eq!(batch.leaves.len(), 2);
        // Both paths have exactly one sibling (the other leaf).
        for proof in &batch.leaves {
            assert_eq!(proof.path.len(), 1);
            assert!(verify_path(&proof.leaf, &proof.path, &batch.root));
        }
    }

    #[test]
    fn three_leaf_odd_duplicates_last() {
        // 3 leaves → at level 0 we have (leaf0, leaf1, leaf2 duplicated).
        // Internal-node pairs: (leaf0, leaf1) and (leaf2, leaf2).
        // Root = sorted_pair_hash(P0, P1) where
        //   P0 = sorted_pair_hash(leaf0, leaf1)
        //   P1 = sorted_pair_hash(leaf2, leaf2)
        let r0 = fixture(100, 1);
        let r1 = fixture(200, 2);
        let r2 = fixture(300, 3);
        let batch = build_merkle(&[r0, r1, r2]).unwrap();
        assert_eq!(batch.leaves.len(), 3);
        // Each path has depth 2.
        for proof in &batch.leaves {
            assert_eq!(proof.path.len(), 2);
            assert!(verify_path(&proof.leaf, &proof.path, &batch.root));
        }
    }

    #[test]
    fn eight_leaf_balanced_tree() {
        let receipts: Vec<Receipt> = (0..8).map(|i| fixture(100 + (i as u64), i as u8)).collect();
        let batch = build_merkle(&receipts).unwrap();
        assert_eq!(batch.leaves.len(), 8);
        // Balanced 8-leaf tree → depth 3.
        for proof in &batch.leaves {
            assert_eq!(proof.path.len(), 3);
            assert!(verify_path(&proof.leaf, &proof.path, &batch.root));
        }
    }

    #[test]
    fn root_independent_of_input_order() {
        let r0 = fixture(100, 1);
        let r1 = fixture(200, 2);
        let r2 = fixture(300, 3);
        let r3 = fixture(400, 4);

        let forward = build_merkle(&[r0.clone(), r1.clone(), r2.clone(), r3.clone()]).unwrap();
        let reverse = build_merkle(&[r3, r2, r1, r0]).unwrap();

        assert_eq!(
            forward.root, reverse.root,
            "Merkle root must be deterministic over the set of leaves, \
             independent of input order"
        );
    }

    #[test]
    fn duplicate_receipt_rejected() {
        let r = fixture(100, 1);
        let err = build_merkle(&[r.clone(), r]).expect_err("duplicate must error");
        match err {
            ReceiptError::BatchInvalid(msg) => {
                assert!(msg.contains("duplicate"), "got: {msg}")
            }
            other => panic!("expected BatchInvalid, got {other:?}"),
        }
    }

    #[test]
    fn tampered_path_fails_verification() {
        let r0 = fixture(100, 1);
        let r1 = fixture(200, 2);
        let batch = build_merkle(&[r0, r1]).unwrap();
        let mut tampered_path = batch.leaves[0].path.clone();
        // Flip one byte of the sibling.
        tampered_path[0].digest[0] ^= 0xAA;
        assert!(!verify_path(
            &batch.leaves[0].leaf,
            &tampered_path,
            &batch.root
        ));
    }

    #[test]
    fn ns_tiebreak_uses_receipt_id() {
        // Two receipts with the same monotonic_ns but different content.
        // Sort must still be total — the receipt_id tiebreaker handles it.
        let r0 = fixture(100, 1);
        let r1 = fixture(100, 2);
        let batch = build_merkle(&[r0.clone(), r1.clone()]).unwrap();
        assert_eq!(batch.leaves.len(), 2);

        // Permuting the input must produce the identical root (the canonical
        // sort is by id when ns ties).
        let batch_rev = build_merkle(&[r1, r0]).unwrap();
        assert_eq!(batch.root, batch_rev.root);
    }
}
