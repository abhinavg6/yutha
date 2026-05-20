//! Canonical-preimage conformance vectors.
//!
//! Loads every JSON fixture under
//! `/spec/vectors/sui-anchoring/preimage/`, feeds the declared inputs
//! into [`yutha_receipt::canonical_preimage`], and asserts byte-equality
//! against the fixture's `expected_preimage_hex`.
//!
//! Sibling Move test in
//! `contracts/sui/receipt_anchor/tests/preimage_vectors_tests.move`
//! loads the same fixtures and asserts the on-chain
//! `build_canonical_preimage` produces the same bytes. The two tests
//! together pin Rust↔Move encoder agreement; any drift fires here
//! at test time rather than at production commit time with a generic
//! `ESealerKeyMismatch`.
//!
//! ## Regenerating expected hex
//!
//! When a deliberate spec change shifts the preimage layout, set
//! `YUTHA_REGENERATE_PREIMAGE_VECTORS=1` and re-run:
//!
//! ```bash
//! YUTHA_REGENERATE_PREIMAGE_VECTORS=1 \
//!   cargo test -p yutha-receipt --test preimage_vectors
//! git diff spec/vectors/sui-anchoring/preimage/
//! ```
//!
//! The test rewrites each fixture's `expected_preimage_hex` in place
//! instead of asserting. Commit the diff, then re-run normally to
//! verify the round-trip.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use yutha_core::{Hash, HashAlgorithm, SwarmId};
use yutha_receipt::canonical_preimage;

/// Top-level vector file shape. Matches the JSON layout documented in
/// `/spec/vectors/sui-anchoring/preimage/README.md`.
#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    name: String,
    description: String,
    inputs: Inputs,
    expected_preimage_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Inputs {
    swarm_id_hex: String,
    batch_root_hex: String,
    count: u64,
    ns_range_start: u64,
    ns_range_end: u64,
    /// `[[action_kind_string, count], ...]`. JSON order is irrelevant —
    /// `canonical_preimage` normalizes via `BTreeMap` to lex-ascending
    /// UTF-8 byte order before encoding.
    histogram: Vec<(String, u64)>,
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string has odd length: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn build_preimage(v: &Vector) -> Vec<u8> {
    let swarm_id_bytes = hex_decode(&v.inputs.swarm_id_hex);
    let swarm_id = SwarmId::from_bytes(&swarm_id_bytes)
        .unwrap_or_else(|e| panic!("[{}] swarm_id: {e}", v.name));

    let batch_root_bytes = hex_decode(&v.inputs.batch_root_hex);
    let batch_root = Hash::new(HashAlgorithm::Sha256, batch_root_bytes)
        .unwrap_or_else(|e| panic!("[{}] batch_root: {e}", v.name));

    let mut histogram = BTreeMap::new();
    for (k, n) in &v.inputs.histogram {
        histogram.insert(k.clone(), *n);
    }

    canonical_preimage(
        &swarm_id,
        &batch_root,
        v.inputs.count,
        v.inputs.ns_range_start,
        v.inputs.ns_range_end,
        &histogram,
    )
    .unwrap_or_else(|e| panic!("[{}] canonical_preimage: {e}", v.name))
}

/// Locate the `/spec/vectors/sui-anchoring/preimage/` directory.
/// Cargo runs integration tests with `CARGO_MANIFEST_DIR =
/// crates/yutha-receipt`; the vectors live four levels up.
fn vectors_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("spec")
        .join("vectors")
        .join("sui-anchoring")
        .join("preimage")
}

fn read_vector_files() -> Vec<PathBuf> {
    let dir = vectors_dir();
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir({}): {e}", dir.display()))
        .filter_map(|entry| {
            let p = entry.ok()?.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    // Stable sort so failures are diffable across runs.
    paths.sort();
    paths
}

#[test]
fn preimage_vectors_match() {
    let regenerate = std::env::var_os("YUTHA_REGENERATE_PREIMAGE_VECTORS").is_some();

    let paths = read_vector_files();
    assert!(
        !paths.is_empty(),
        "no preimage vector fixtures found in {}",
        vectors_dir().display()
    );

    let mut failures: Vec<String> = Vec::new();
    for path in paths {
        let raw =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut vector: Vector = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse {} as Vector: {e}", path.display()));

        let computed = build_preimage(&vector);
        let computed_hex = hex_encode(&computed);

        if regenerate {
            if vector.expected_preimage_hex != computed_hex {
                vector.expected_preimage_hex = computed_hex.clone();
                let serialized = serde_json::to_string_pretty(&vector).expect("serialize Vector");
                fs::write(&path, serialized + "\n")
                    .unwrap_or_else(|e| panic!("rewrite {}: {e}", path.display()));
            }
            continue;
        }

        if vector.expected_preimage_hex != computed_hex {
            failures.push(format!(
                "[{}] mismatch:\n  expected: {}\n  computed: {}",
                vector.name, vector.expected_preimage_hex, computed_hex,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "preimage-vector mismatches:\n{}",
        failures.join("\n")
    );
}
