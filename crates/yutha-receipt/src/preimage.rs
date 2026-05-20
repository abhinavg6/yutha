//! Canonical preimage encoder for the on-chain anchor signature.
//!
//! Implements the byte-exact preimage layout specified in
//! [`/spec/verifiability/sui-anchoring.md`](../../../spec/verifiability/sui-anchoring.md)
//! §4. This is what the sealer's Ed25519 key signs, and what the Move
//! module's `commit_batch` function reconstructs byte-for-byte before
//! calling Sui's native `ed25519_verify`.
//!
//! The encoding is intentionally simple (fixed-width fields, BE
//! integers, no length-prefixed strings except for the histogram
//! entries' keys, no nested protobuf). The goal is to be reproducible
//! in Move with no third-party dependency beyond the Sui stdlib.
//!
//! ## Layout (matches the spec §4)
//!
//! ```text
//! preimage =
//!     swarm_id          (16 bytes)              ‖
//!     batch_root        (32 bytes)              ‖
//!     count             (u64 BE, 8 bytes)       ‖
//!     ns_range_start    (u64 BE, 8 bytes)       ‖
//!     ns_range_end      (u64 BE, 8 bytes)       ‖
//!     canonical_histogram_bytes
//! ```
//!
//! ## Histogram layout (matches §4.1)
//!
//! ```text
//! canonical_histogram_bytes =
//!     entry_count       (u32 BE, 4 bytes)       ‖
//!     entries (sorted lex-ascending by action_kind):
//!         action_kind_len    (u8, 1 byte)       ‖
//!         action_kind        (UTF-8, action_kind_len bytes) ‖
//!         count              (u64 BE, 8 bytes)
//! ```

use std::collections::BTreeMap;

use yutha_core::{Hash, SwarmId};

use crate::{ReceiptError, Result};

/// Maximum length of an action_kind string in the canonical histogram.
/// Self-enforced by the u8 wire encoding; mirrored at the Move side
/// (`EHistogramKeyTooLong`).
pub const MAX_ACTION_KIND_LEN: usize = 255;

/// Build the canonical signing preimage for an anchor batch.
///
/// Returns the bytes the sealer's Ed25519 key signs and the Move
/// module reconstructs to verify.
///
/// Validation performed here (all rejected before returning):
/// - `swarm_id` has the correct 16-byte length (enforced by the type).
/// - `batch_root` is a SHA-256 hash (32-byte digest) — enforced by [`Hash::validate`].
/// - `count` matches `sum(histogram.values())`.
/// - `ns_range_start <= ns_range_end`.
/// - Each `action_kind` is non-empty and at most [`MAX_ACTION_KIND_LEN`] bytes.
/// - Each histogram entry's value is non-zero (zero counts MUST NOT be encoded).
/// - The histogram is non-empty (a batch always has at least one receipt).
pub fn canonical_preimage(
    swarm_id: &SwarmId,
    batch_root: &Hash,
    count: u64,
    ns_range_start: u64,
    ns_range_end: u64,
    histogram: &BTreeMap<String, u64>,
) -> Result<Vec<u8>> {
    // Structural validation first; cheaper to surface a clear error
    // than to emit malformed bytes the on-chain verify would reject.
    batch_root.validate()?;

    if ns_range_start > ns_range_end {
        return Err(ReceiptError::BatchInvalid(format!(
            "ns_range_start ({ns_range_start}) > ns_range_end ({ns_range_end})"
        )));
    }
    if histogram.is_empty() {
        return Err(ReceiptError::BatchInvalid(
            "histogram must be non-empty".into(),
        ));
    }

    let mut histogram_sum: u64 = 0;
    for (kind, &k_count) in histogram {
        if kind.is_empty() {
            return Err(ReceiptError::BatchInvalid(
                "action_kind keys must be non-empty".into(),
            ));
        }
        if kind.len() > MAX_ACTION_KIND_LEN {
            return Err(ReceiptError::BatchInvalid(format!(
                "action_kind {kind:?} exceeds {MAX_ACTION_KIND_LEN}-byte limit \
                 (got {len} bytes)",
                len = kind.len()
            )));
        }
        if k_count == 0 {
            return Err(ReceiptError::BatchInvalid(format!(
                "histogram value for action_kind {kind:?} is zero; \
                 zero-count entries MUST NOT be encoded"
            )));
        }
        histogram_sum = histogram_sum
            .checked_add(k_count)
            .ok_or_else(|| ReceiptError::BatchInvalid("histogram sum overflows u64".into()))?;
    }

    if histogram_sum != count {
        return Err(ReceiptError::BatchInvalid(format!(
            "histogram values sum to {histogram_sum} but count is {count}"
        )));
    }

    let entry_count: u32 = histogram.len().try_into().map_err(|_| {
        ReceiptError::BatchInvalid(format!(
            "histogram has more than u32::MAX entries ({})",
            histogram.len()
        ))
    })?;

    // Reserve a generous initial capacity:
    //   16 (swarm_id) + 32 (batch_root) + 24 (three u64s) + 4 (entry_count)
    //   + entries.len() * (1 + avg_key_len + 8)
    let avg_key_len = 32; // heuristic; canonical kinds are typically ~25 bytes
    let cap = 76 + histogram.len() * (1 + avg_key_len + 8);
    let mut buf = Vec::with_capacity(cap);

    buf.extend_from_slice(&swarm_id.as_bytes());
    buf.extend_from_slice(&batch_root.digest);
    buf.extend_from_slice(&count.to_be_bytes());
    buf.extend_from_slice(&ns_range_start.to_be_bytes());
    buf.extend_from_slice(&ns_range_end.to_be_bytes());

    buf.extend_from_slice(&entry_count.to_be_bytes());

    // BTreeMap iterates by key in lex-ascending byte order for `String`,
    // which is exactly the canonical sort order the spec specifies
    // (UTF-8 byte ordering = lex-ascending for distinct keys, and
    // `String`'s Ord uses byte order).
    for (kind, &k_count) in histogram {
        let kind_bytes = kind.as_bytes();
        // Length-bound check above guarantees this fits in u8.
        buf.push(kind_bytes.len() as u8);
        buf.extend_from_slice(kind_bytes);
        buf.extend_from_slice(&k_count.to_be_bytes());
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_core::HashAlgorithm;

    fn h(byte: u8) -> Hash {
        Hash::new(HashAlgorithm::Sha256, vec![byte; 32]).unwrap()
    }

    fn s(byte: u8) -> SwarmId {
        SwarmId::from_bytes(&[byte; 16]).unwrap()
    }

    fn one_kind(name: &str, n: u64) -> BTreeMap<String, u64> {
        let mut m = BTreeMap::new();
        m.insert(name.into(), n);
        m
    }

    #[test]
    fn single_kind_minimal_batch() {
        let mut hist = one_kind("envelope.send", 1);
        let bytes = canonical_preimage(&s(0xAA), &h(0xBB), 1, 100, 100, &hist).unwrap();

        // 16 + 32 + 8 + 8 + 8 + 4 + 1 + 13 + 8 = 98 bytes.
        assert_eq!(bytes.len(), 98);

        // First 16 bytes = swarm_id (0xAA × 16)
        assert_eq!(&bytes[..16], &[0xAA; 16][..]);
        // Next 32 = batch_root (0xBB × 32)
        assert_eq!(&bytes[16..48], &[0xBB; 32][..]);
        // Next 8 = count = 1 (u64 BE)
        assert_eq!(&bytes[48..56], &1u64.to_be_bytes()[..]);
        // Next 8 = ns_range_start = 100
        assert_eq!(&bytes[56..64], &100u64.to_be_bytes()[..]);
        // Next 8 = ns_range_end = 100
        assert_eq!(&bytes[64..72], &100u64.to_be_bytes()[..]);
        // Next 4 = entry_count = 1
        assert_eq!(&bytes[72..76], &1u32.to_be_bytes()[..]);
        // Next 1 = action_kind_len = len("envelope.send") = 13
        assert_eq!(bytes[76], 13);
        // Next 13 = action_kind bytes
        assert_eq!(&bytes[77..90], b"envelope.send");
        // Final 8 = count for this kind = 1
        assert_eq!(&bytes[90..98], &1u64.to_be_bytes()[..]);

        // Cleanup unused var warning.
        hist.clear();
    }

    #[test]
    fn multi_kind_sorted_lexicographically() {
        // Insert in non-sorted order; BTreeMap normalizes.
        let mut hist = BTreeMap::new();
        hist.insert("envelope.send".into(), 5);
        hist.insert("agent.register".into(), 1);
        hist.insert("envelope.deliver".into(), 5);

        let bytes = canonical_preimage(&s(0), &h(0), 11, 0, 1000, &hist).unwrap();

        // After the 76-byte header (swarm_id + batch_root + 3×u64 + u32),
        // entries begin. Expected key order (lex-ascending UTF-8):
        //   1. "agent.register" (len=14)
        //   2. "envelope.deliver" (len=16)
        //   3. "envelope.send" (len=13)
        let mut pos = 76;
        assert_eq!(bytes[pos], 14);
        pos += 1;
        assert_eq!(&bytes[pos..pos + 14], b"agent.register");
        pos += 14;
        assert_eq!(&bytes[pos..pos + 8], &1u64.to_be_bytes()[..]);
        pos += 8;

        assert_eq!(bytes[pos], 16);
        pos += 1;
        assert_eq!(&bytes[pos..pos + 16], b"envelope.deliver");
        pos += 16;
        assert_eq!(&bytes[pos..pos + 8], &5u64.to_be_bytes()[..]);
        pos += 8;

        assert_eq!(bytes[pos], 13);
        pos += 1;
        assert_eq!(&bytes[pos..pos + 13], b"envelope.send");
        pos += 13;
        assert_eq!(&bytes[pos..pos + 8], &5u64.to_be_bytes()[..]);
        pos += 8;

        assert_eq!(pos, bytes.len(), "no trailing bytes");
    }

    #[test]
    fn determinism_across_btreemap_insertion_orders() {
        let mut a = BTreeMap::new();
        a.insert("x".into(), 1);
        a.insert("y".into(), 2);
        a.insert("z".into(), 3);

        let mut b = BTreeMap::new();
        b.insert("z".into(), 3);
        b.insert("x".into(), 1);
        b.insert("y".into(), 2);

        let bytes_a = canonical_preimage(&s(0), &h(0), 6, 0, 0, &a).unwrap();
        let bytes_b = canonical_preimage(&s(0), &h(0), 6, 0, 0, &b).unwrap();
        assert_eq!(
            bytes_a, bytes_b,
            "preimage must be deterministic regardless of insertion order"
        );
    }

    #[test]
    fn workload_namespaced_action_kinds() {
        // Workload-extension action_kinds (Yutha::SupportQueue::Action::IssueRefund
        // etc.) are longer than canonical ones — sanity-check they
        // encode correctly within the u8 length bound.
        let mut hist = BTreeMap::new();
        hist.insert("Yutha::SupportQueue::Action::IssueRefund".into(), 3);
        hist.insert("envelope.send".into(), 10);

        let bytes = canonical_preimage(&s(1), &h(2), 13, 100, 200, &hist).unwrap();

        // Find the workload kind in the output.
        let kind = b"Yutha::SupportQueue::Action::IssueRefund";
        let prefix_byte = kind.len() as u8;
        // Search for [prefix_byte, ...kind...] at any position.
        let needle: Vec<u8> = std::iter::once(prefix_byte)
            .chain(kind.iter().copied())
            .collect();
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "workload-namespaced action_kind not found in preimage"
        );
    }

    #[test]
    fn unicode_action_kind_byte_ordering() {
        // Three keys whose UTF-8 byte orderings differ from lexicographic
        // string-Ord on Unicode codepoints. (BTreeMap<String> uses Ord
        // which delegates to str's Ord, which IS byte-order for UTF-8.
        // So this should match the spec's "UTF-8 byte ordering" rule.)
        let mut hist = BTreeMap::new();
        hist.insert("apple".into(), 1);
        hist.insert("Δapple".into(), 1); // Δ is 0xCE 0x94 in UTF-8
        hist.insert("zapple".into(), 1);

        let bytes = canonical_preimage(&s(0), &h(0), 3, 0, 0, &hist).unwrap();

        // Expected order by UTF-8 byte values:
        //   - "apple" starts with 0x61 ('a')
        //   - "zapple" starts with 0x7A ('z')
        //   - "Δapple" starts with 0xCE
        // So order is: apple, zapple, Δapple
        let after_header = &bytes[76..];
        assert_eq!(after_header[0], 5); // len("apple") = 5
        assert_eq!(&after_header[1..6], b"apple");

        let mut pos = 1 + 5 + 8; // len byte + key + count
        assert_eq!(after_header[pos], 6); // len("zapple") = 6
        assert_eq!(&after_header[pos + 1..pos + 7], b"zapple");
        pos += 1 + 6 + 8;

        // "Δapple" is 2 + 5 = 7 bytes
        assert_eq!(after_header[pos], 7);
        assert_eq!(&after_header[pos + 1..pos + 1 + 7], "Δapple".as_bytes());
    }

    #[test]
    fn rejects_empty_histogram() {
        let hist = BTreeMap::new();
        let err = canonical_preimage(&s(0), &h(0), 0, 0, 0, &hist).unwrap_err();
        match err {
            ReceiptError::BatchInvalid(msg) => assert!(msg.contains("non-empty")),
            other => panic!("expected BatchInvalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_count_mismatch() {
        let hist = one_kind("foo", 5);
        // Histogram sums to 5 but we claim count=10.
        let err = canonical_preimage(&s(0), &h(0), 10, 0, 0, &hist).unwrap_err();
        match err {
            ReceiptError::BatchInvalid(msg) => {
                assert!(msg.contains("sum to 5") && msg.contains("count is 10"))
            }
            other => panic!("expected BatchInvalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_count_entry() {
        let mut hist = BTreeMap::new();
        hist.insert("foo".into(), 1);
        hist.insert("bar".into(), 0); // zero-count entry forbidden
        let err = canonical_preimage(&s(0), &h(0), 1, 0, 0, &hist).unwrap_err();
        match err {
            ReceiptError::BatchInvalid(msg) => assert!(msg.contains("zero")),
            other => panic!("expected BatchInvalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_action_kind() {
        let hist = one_kind("", 1);
        let err = canonical_preimage(&s(0), &h(0), 1, 0, 0, &hist).unwrap_err();
        match err {
            ReceiptError::BatchInvalid(msg) => assert!(msg.contains("non-empty")),
            other => panic!("expected BatchInvalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_overlong_action_kind() {
        let long_kind: String = "x".repeat(MAX_ACTION_KIND_LEN + 1);
        let hist = one_kind(&long_kind, 1);
        let err = canonical_preimage(&s(0), &h(0), 1, 0, 0, &hist).unwrap_err();
        match err {
            ReceiptError::BatchInvalid(msg) => assert!(msg.contains("exceeds")),
            other => panic!("expected BatchInvalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_ns_range_inversion() {
        let hist = one_kind("foo", 1);
        let err = canonical_preimage(&s(0), &h(0), 1, 200, 100, &hist).unwrap_err();
        match err {
            ReceiptError::BatchInvalid(msg) => assert!(msg.contains("ns_range_start")),
            other => panic!("expected BatchInvalid, got {other:?}"),
        }
    }

    #[test]
    fn accepts_max_length_action_kind() {
        let kind: String = "x".repeat(MAX_ACTION_KIND_LEN);
        let hist = one_kind(&kind, 1);
        let bytes = canonical_preimage(&s(0), &h(0), 1, 0, 0, &hist).unwrap();
        // Header: 76 bytes. Entry: 1 (len) + 255 (key) + 8 (count) = 264.
        assert_eq!(bytes.len(), 76 + 264);
    }
}
